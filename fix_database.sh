#!/bin/bash
# fix_database.sh - Comprehensive database fix solution
set -euo pipefail

echo "🔧 CRYPTO HUNTER - Database Fix Utility"
echo "======================================"
echo ""
echo "This script provides multiple options to fix database issues:"
echo ""
echo "1. Fix specific issues (preserves data)"
echo "2. Validate database schema"
echo "3. Complete database reset (WARNING: deletes all data)"
echo "4. Exit"
echo ""

read -p "Enter your choice (1-4): " choice

# Check if running in Docker environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup; then
    INSIDE_DOCKER=true
    echo "Running inside Docker container"
else
    INSIDE_DOCKER=false
    echo "Running outside Docker container"
fi

# Function to execute SQL
execute_sql() {
    local sql="$1"

    if [ "$INSIDE_DOCKER" = true ]; then
        # Inside Docker container
        echo "$sql" | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
    else
        # Outside Docker container, use docker compose
        echo "$sql" | docker compose exec -T db psql -U crypto_hunter -d crypto_hunter
    fi
}

# Function to check database connection
check_db_connection() {
    echo "📊 Checking database connection..."
    if [ "$INSIDE_DOCKER" = true ]; then
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1" > /dev/null
    else
        docker compose exec db psql -U crypto_hunter -d crypto_hunter -c "SELECT 1" > /dev/null
    fi
    echo "✅ Database connection successful"
}

# Function to fix specific issues
fix_specific_issues() {
    echo "🔍 Fixing specific database issues..."

    # Check database connection
    check_db_connection

    # 1. Fix missing task_id column in bulk_imports table
    echo "  - Checking for missing task_id column in bulk_imports table"

    # First check if the bulk_imports table exists
    TABLE_EXISTS=$(execute_sql "
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'bulk_imports'
    );
    " | grep -c "t" || true)

    if [ "$TABLE_EXISTS" -gt 0 ]; then
        echo "    ✅ bulk_imports table exists"

        # Check if task_id column exists
        TASK_ID_EXISTS=$(execute_sql "
        SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = 'bulk_imports' AND column_name = 'task_id'
        );
        " | grep -c "t" || true)

        if [ "$TASK_ID_EXISTS" -gt 0 ]; then
            echo "    ✅ task_id column already exists in bulk_imports table"
        else
            echo "    ❌ task_id column missing from bulk_imports table"
            echo "    - Adding task_id column to bulk_imports table"

            execute_sql "
            ALTER TABLE bulk_imports ADD COLUMN IF NOT EXISTS task_id VARCHAR(36);
            CREATE INDEX IF NOT EXISTS idx_bulk_imports_task_id ON bulk_imports(task_id);
            "

            # Verify the column was added
            TASK_ID_ADDED=$(execute_sql "
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'bulk_imports' AND column_name = 'task_id';
            " | grep -c "task_id" || true)

            if [ "$TASK_ID_ADDED" -gt 0 ]; then
                echo "    ✅ task_id column added successfully to bulk_imports table"
            else
                echo "    ❌ Failed to add task_id column to bulk_imports table"
                exit 1
            fi
        fi
    else
        echo "    ⚠️ bulk_imports table does not exist yet - it will be created when needed"
    fi

    echo ""
    echo "✅ All specific issues fixed successfully!"
}

# Function to validate database schema
validate_schema() {
    echo "🔍 Validating database schema..."

    # Check if export_db_schema.py exists and is executable
    if [ -f "./export_db_schema.py" ] && [ -x "./export_db_schema.py" ]; then
        ./export_db_schema.py
    else
        echo "❌ export_db_schema.py not found or not executable"
        echo "Creating executable script..."

        # Make the script executable if it exists but isn't executable
        if [ -f "./export_db_schema.py" ]; then
            chmod +x ./export_db_schema.py
            ./export_db_schema.py
        else
            echo "❌ export_db_schema.py not found. Please run this script from the project root directory."
            exit 1
        fi
    fi
}

# Function to reset the database completely
reset_database() {
    echo "⚠️ WARNING: This will delete all data in the database and recreate the tables."
    echo "⚠️ All existing data will be lost."
    read -p "Are you sure you want to continue? (y/N): " confirm

    if [[ "$confirm" != [yY] ]]; then
        echo "Database reset cancelled."
        exit 0
    fi

    echo "🔄 Resetting database..."

    # Check database connection
    check_db_connection

    # Drop and recreate all tables
    if [ "$INSIDE_DOCKER" = true ]; then
        # Inside Docker container
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" << 'EOF'
        -- Drop existing tables
        DROP TABLE IF EXISTS findings CASCADE;
        DROP TABLE IF EXISTS vectors CASCADE;
        DROP TABLE IF EXISTS api_keys CASCADE;
        DROP TABLE IF EXISTS audit_logs CASCADE;
        DROP TABLE IF EXISTS file_content CASCADE;
        DROP TABLE IF EXISTS combination_sources CASCADE;
        DROP TABLE IF EXISTS combination_relationships CASCADE;
        DROP TABLE IF EXISTS extraction_relationships CASCADE;
        DROP TABLE IF EXISTS file_derivations CASCADE;
        DROP TABLE IF EXISTS regions_of_interest CASCADE;
        DROP TABLE IF EXISTS graph_edges CASCADE;
        DROP TABLE IF EXISTS file_nodes CASCADE;
        DROP TABLE IF EXISTS analysis_files CASCADE;
        DROP TABLE IF EXISTS users CASCADE;
        DROP TABLE IF EXISTS bulk_imports CASCADE;

        -- Create users table
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            display_name VARCHAR(100),
            first_name VARCHAR(50),
            last_name VARCHAR(50),
            avatar_url VARCHAR(255),
            is_admin BOOLEAN DEFAULT FALSE,
            is_verified BOOLEAN DEFAULT FALSE,
            level VARCHAR(12) DEFAULT 'ANALYST',
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            two_factor_secret VARCHAR(32),
            api_key_hash VARCHAR(255),
            timezone VARCHAR(50) DEFAULT 'UTC',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            last_login_at TIMESTAMP
        );

        -- Create analysis_files table
        CREATE TABLE analysis_files (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            filename VARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            file_type VARCHAR(100),
            mime_type VARCHAR(100),
            sha256_hash VARCHAR(64) UNIQUE NOT NULL,
            md5_hash VARCHAR(32),
            sha1_hash VARCHAR(40),
            crc32 VARCHAR(8),
            status VARCHAR(50) DEFAULT 'pending',
            is_encrypted BOOLEAN DEFAULT FALSE,
            encryption_type VARCHAR(50),
            contains_crypto BOOLEAN DEFAULT FALSE,
            crypto_confidence FLOAT DEFAULT 0.0,
            tags JSONB DEFAULT '[]'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            notes TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            analyzed_at TIMESTAMP
        );

        -- Create file_content table
        CREATE TABLE file_content (
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            content_type VARCHAR(50) NOT NULL,
            content_format VARCHAR(50) NOT NULL,
            content BYTEA,
            text_content TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create findings table
        CREATE TABLE findings (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            finding_type VARCHAR(100) NOT NULL,
            category VARCHAR(50),
            subcategory VARCHAR(50),
            confidence FLOAT DEFAULT 0.0,
            severity VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'unverified',
            title VARCHAR(255),
            description TEXT,
            details JSONB DEFAULT '{}'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            start_offset BIGINT,
            end_offset BIGINT,
            line_number INTEGER,
            column_number INTEGER,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            verified_by INTEGER REFERENCES users(id),
            verified_at TIMESTAMP
        );

        -- Create vectors table
        CREATE TABLE vectors (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
            vector_type VARCHAR(50) NOT NULL,
            embedding_model VARCHAR(100),
            embedding FLOAT[] NOT NULL,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create api_keys table
        CREATE TABLE api_keys (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            key_hash VARCHAR(255) NOT NULL,
            scopes VARCHAR(255)[],
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW(),
            last_used_at TIMESTAMP
        );

        -- Create audit_logs table
        CREATE TABLE audit_logs (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(50) NOT NULL,
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            details JSONB DEFAULT '{}'::jsonb,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create extraction_relationships table
        CREATE TABLE extraction_relationships (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            source_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            extracted_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            source_file_sha VARCHAR(64) NOT NULL,
            extracted_file_sha VARCHAR(64) NOT NULL,
            extraction_method VARCHAR(100) NOT NULL,
            confidence FLOAT DEFAULT 1.0,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            created_by INTEGER REFERENCES users(id)
        );

        -- Create file_nodes table
        CREATE TABLE file_nodes (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            file_sha VARCHAR(64) NOT NULL,
            node_type VARCHAR(50) NOT NULL,
            properties JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create graph_edges table
        CREATE TABLE graph_edges (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            source_node_id INTEGER REFERENCES file_nodes(id) ON DELETE CASCADE,
            target_node_id INTEGER REFERENCES file_nodes(id) ON DELETE CASCADE,
            edge_type VARCHAR(50) NOT NULL,
            weight FLOAT DEFAULT 1.0,
            properties JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create regions_of_interest table
        CREATE TABLE regions_of_interest (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            title VARCHAR(255),
            description TEXT,
            region_type VARCHAR(50) NOT NULL,
            start_offset BIGINT NOT NULL,
            end_offset BIGINT NOT NULL,
            content BYTEA,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create file_derivations table
        CREATE TABLE file_derivations (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            parent_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            child_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            parent_sha VARCHAR(64) NOT NULL,
            child_sha VARCHAR(64) NOT NULL,
            operation VARCHAR(100) NOT NULL,
            parameters JSONB DEFAULT '{}'::jsonb,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create combination_relationships table
        CREATE TABLE combination_relationships (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            result_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            combination_method VARCHAR(100) NOT NULL,
            notes TEXT,
            discovered_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create combination_sources table
        CREATE TABLE combination_sources (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            combination_id INTEGER REFERENCES combination_relationships(id) ON DELETE CASCADE,
            source_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            order_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create bulk_imports table
        CREATE TABLE bulk_imports (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            import_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            total_items INTEGER DEFAULT 0,
            processed_items INTEGER DEFAULT 0,
            successful_items INTEGER DEFAULT 0,
            failed_items INTEGER DEFAULT 0,
            task_id VARCHAR(36),
            error_message TEXT,
            error_details JSONB DEFAULT '{}'::jsonb,
            source_file VARCHAR(255),
            file_size BIGINT,
            file_hash VARCHAR(64),
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            completed_at TIMESTAMP
        );

        -- Create indexes for performance
        CREATE INDEX idx_files_sha256 ON analysis_files(sha256_hash);
        CREATE INDEX idx_files_status ON analysis_files(status);
        CREATE INDEX idx_findings_type ON findings(finding_type);
        CREATE INDEX idx_findings_confidence ON findings(confidence);
        CREATE INDEX idx_vectors_file_id ON vectors(file_id);
        CREATE INDEX idx_file_content_file_id ON file_content(file_id);
        CREATE INDEX idx_extraction_source_file ON extraction_relationships(source_file_id);
        CREATE INDEX idx_extraction_extracted_file ON extraction_relationships(extracted_file_id);
        CREATE INDEX idx_file_nodes_file_id ON file_nodes(file_id);
        CREATE INDEX idx_graph_edges_source ON graph_edges(source_node_id);
        CREATE INDEX idx_graph_edges_target ON graph_edges(target_node_id);
        CREATE INDEX idx_bulk_imports_task_id ON bulk_imports(task_id);

        -- Insert admin user
        INSERT INTO users (
            public_id, username, email, password_hash, display_name, 
            is_admin, is_verified, level, created_at, updated_at
        )
        VALUES (
            gen_random_uuid(),
            'admin',
            'admin@example.com',
            '$2b$12$LQv3c1yqBwEHFqTh4Q8K.uEH0yJ02XFi7V2nk9L4o6yKZB1Q7ZQ7S',
            'Administrator',
            true,
            true,
            'MASTER',
            NOW(),
            NOW()
        ) ON CONFLICT (username) DO NOTHING;

        -- Show created tables
        \dt

        -- Show admin user
        SELECT username, email, is_admin, level, created_at FROM users WHERE username='admin';
EOF
    else
        # Outside Docker container
        docker compose exec db psql -U crypto_hunter -d crypto_hunter << 'EOF'
        -- Drop existing tables
        DROP TABLE IF EXISTS findings CASCADE;
        DROP TABLE IF EXISTS vectors CASCADE;
        DROP TABLE IF EXISTS api_keys CASCADE;
        DROP TABLE IF EXISTS audit_logs CASCADE;
        DROP TABLE IF EXISTS file_content CASCADE;
        DROP TABLE IF EXISTS combination_sources CASCADE;
        DROP TABLE IF EXISTS combination_relationships CASCADE;
        DROP TABLE IF EXISTS extraction_relationships CASCADE;
        DROP TABLE IF EXISTS file_derivations CASCADE;
        DROP TABLE IF EXISTS regions_of_interest CASCADE;
        DROP TABLE IF EXISTS graph_edges CASCADE;
        DROP TABLE IF EXISTS file_nodes CASCADE;
        DROP TABLE IF EXISTS analysis_files CASCADE;
        DROP TABLE IF EXISTS users CASCADE;
        DROP TABLE IF EXISTS bulk_imports CASCADE;

        -- Create users table
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            display_name VARCHAR(100),
            first_name VARCHAR(50),
            last_name VARCHAR(50),
            avatar_url VARCHAR(255),
            is_admin BOOLEAN DEFAULT FALSE,
            is_verified BOOLEAN DEFAULT FALSE,
            level VARCHAR(12) DEFAULT 'ANALYST',
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            two_factor_secret VARCHAR(32),
            api_key_hash VARCHAR(255),
            timezone VARCHAR(50) DEFAULT 'UTC',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            last_login_at TIMESTAMP
        );

        -- Create analysis_files table
        CREATE TABLE analysis_files (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            filename VARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            file_type VARCHAR(100),
            mime_type VARCHAR(100),
            sha256_hash VARCHAR(64) UNIQUE NOT NULL,
            md5_hash VARCHAR(32),
            sha1_hash VARCHAR(40),
            crc32 VARCHAR(8),
            status VARCHAR(50) DEFAULT 'pending',
            is_encrypted BOOLEAN DEFAULT FALSE,
            encryption_type VARCHAR(50),
            contains_crypto BOOLEAN DEFAULT FALSE,
            crypto_confidence FLOAT DEFAULT 0.0,
            tags JSONB DEFAULT '[]'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            notes TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            analyzed_at TIMESTAMP
        );

        -- Create file_content table
        CREATE TABLE file_content (
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            content_type VARCHAR(50) NOT NULL,
            content_format VARCHAR(50) NOT NULL,
            content BYTEA,
            text_content TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create findings table
        CREATE TABLE findings (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            finding_type VARCHAR(100) NOT NULL,
            category VARCHAR(50),
            subcategory VARCHAR(50),
            confidence FLOAT DEFAULT 0.0,
            severity VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'unverified',
            title VARCHAR(255),
            description TEXT,
            details JSONB DEFAULT '{}'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            start_offset BIGINT,
            end_offset BIGINT,
            line_number INTEGER,
            column_number INTEGER,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            verified_by INTEGER REFERENCES users(id),
            verified_at TIMESTAMP
        );

        -- Create vectors table
        CREATE TABLE vectors (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
            vector_type VARCHAR(50) NOT NULL,
            embedding_model VARCHAR(100),
            embedding FLOAT[] NOT NULL,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create api_keys table
        CREATE TABLE api_keys (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            key_hash VARCHAR(255) NOT NULL,
            scopes VARCHAR(255)[],
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW(),
            last_used_at TIMESTAMP
        );

        -- Create audit_logs table
        CREATE TABLE audit_logs (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(50) NOT NULL,
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            details JSONB DEFAULT '{}'::jsonb,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create extraction_relationships table
        CREATE TABLE extraction_relationships (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            source_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            extracted_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            source_file_sha VARCHAR(64) NOT NULL,
            extracted_file_sha VARCHAR(64) NOT NULL,
            extraction_method VARCHAR(100) NOT NULL,
            confidence FLOAT DEFAULT 1.0,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            created_by INTEGER REFERENCES users(id)
        );

        -- Create file_nodes table
        CREATE TABLE file_nodes (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            file_sha VARCHAR(64) NOT NULL,
            node_type VARCHAR(50) NOT NULL,
            properties JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create graph_edges table
        CREATE TABLE graph_edges (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            source_node_id INTEGER REFERENCES file_nodes(id) ON DELETE CASCADE,
            target_node_id INTEGER REFERENCES file_nodes(id) ON DELETE CASCADE,
            edge_type VARCHAR(50) NOT NULL,
            weight FLOAT DEFAULT 1.0,
            properties JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create regions_of_interest table
        CREATE TABLE regions_of_interest (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            title VARCHAR(255),
            description TEXT,
            region_type VARCHAR(50) NOT NULL,
            start_offset BIGINT NOT NULL,
            end_offset BIGINT NOT NULL,
            content BYTEA,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create file_derivations table
        CREATE TABLE file_derivations (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            parent_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            child_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            parent_sha VARCHAR(64) NOT NULL,
            child_sha VARCHAR(64) NOT NULL,
            operation VARCHAR(100) NOT NULL,
            parameters JSONB DEFAULT '{}'::jsonb,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create combination_relationships table
        CREATE TABLE combination_relationships (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            result_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            combination_method VARCHAR(100) NOT NULL,
            notes TEXT,
            discovered_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Create combination_sources table
        CREATE TABLE combination_sources (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            combination_id INTEGER REFERENCES combination_relationships(id) ON DELETE CASCADE,
            source_file_id INTEGER REFERENCES analysis_files(id) ON DELETE CASCADE,
            order_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Create bulk_imports table
        CREATE TABLE bulk_imports (
            id SERIAL PRIMARY KEY,
            public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
            import_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            total_items INTEGER DEFAULT 0,
            processed_items INTEGER DEFAULT 0,
            successful_items INTEGER DEFAULT 0,
            failed_items INTEGER DEFAULT 0,
            task_id VARCHAR(36),
            error_message TEXT,
            error_details JSONB DEFAULT '{}'::jsonb,
            source_file VARCHAR(255),
            file_size BIGINT,
            file_hash VARCHAR(64),
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            completed_at TIMESTAMP
        );

        -- Create indexes for performance
        CREATE INDEX idx_files_sha256 ON analysis_files(sha256_hash);
        CREATE INDEX idx_files_status ON analysis_files(status);
        CREATE INDEX idx_findings_type ON findings(finding_type);
        CREATE INDEX idx_findings_confidence ON findings(confidence);
        CREATE INDEX idx_vectors_file_id ON vectors(file_id);
        CREATE INDEX idx_file_content_file_id ON file_content(file_id);
        CREATE INDEX idx_extraction_source_file ON extraction_relationships(source_file_id);
        CREATE INDEX idx_extraction_extracted_file ON extraction_relationships(extracted_file_id);
        CREATE INDEX idx_file_nodes_file_id ON file_nodes(file_id);
        CREATE INDEX idx_graph_edges_source ON graph_edges(source_node_id);
        CREATE INDEX idx_graph_edges_target ON graph_edges(target_node_id);
        CREATE INDEX idx_bulk_imports_task_id ON bulk_imports(task_id);

        -- Insert admin user
        INSERT INTO users (
            public_id, username, email, password_hash, display_name, 
            is_admin, is_verified, level, created_at, updated_at
        )
        VALUES (
            gen_random_uuid(),
            'admin',
            'admin@example.com',
            '$2b$12$LQv3c1yqBwEHFqTh4Q8K.uEH0yJ02XFi7V2nk9L4o6yKZB1Q7ZQ7S',
            'Administrator',
            true,
            true,
            'MASTER',
            NOW(),
            NOW()
        ) ON CONFLICT (username) DO NOTHING;

        -- Show created tables
        \dt

        -- Show admin user
        SELECT username, email, is_admin, level, created_at FROM users WHERE username='admin';
EOF
    fi

    echo ""
    echo "✅ Database reset completed successfully!"
    echo ""
    echo "🎉 CRYPTO HUNTER IS READY!"
    echo "================================"
    echo ""
    echo "🔐 Login Credentials:"
    echo "   Username: admin"
    echo "   Password: admin123"
    echo ""
}

# Main logic based on user choice
case $choice in
    1)
        fix_specific_issues
        ;;
    2)
        validate_schema
        ;;
    3)
        reset_database
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

echo ""
echo "📊 Database Management Commands:"
echo "   Fix specific issues:  ./fix_database.sh  # then select option 1"
echo "   Validate schema:      ./export_db_schema.py"
echo "   Reset database:       ./fix_database.sh  # then select option 3"
echo ""
echo "📚 For more information, see DATABASE_MAINTENANCE.md"
echo ""
