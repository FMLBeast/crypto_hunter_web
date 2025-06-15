import pytest
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash

from crypto_hunter_web.models import User, AuditLog, UserLevel, AnalysisFile, FileStatus, Finding, FindingStatus, FileContent, RegionOfInterest


class TestUserModel:
    """Test suite for the User model."""

    def test_user_creation(self, session):
        """Test creating a new user."""
        user = User(
            username='newuser',
            email='newuser@example.com',
            is_active=True,
            is_admin=False
        )
        user.set_password('securepass123')
        session.add(user)
        session.commit()

        # Retrieve the user from the database
        saved_user = User.query.filter_by(username='newuser').first()

        # Check that user was saved correctly
        assert saved_user is not None
        assert saved_user.username == 'newuser'
        assert saved_user.email == 'newuser@example.com'
        assert saved_user.is_active is True
        assert saved_user.is_admin is False
        assert saved_user.level == UserLevel.ANALYST  # Default level
        assert saved_user.points == 0  # Default points
        assert saved_user.check_password('securepass123') is True

    def test_user_password_hashing(self, session):
        """Test password hashing functionality."""
        user = User(username='passuser', email='pass@example.com')

        # Set password and check that it's hashed
        user.set_password('password123')
        assert user.password_hash is not None
        assert user.password_hash != 'password123'
        assert check_password_hash(user.password_hash, 'password123') is True

        # Check that password verification works
        assert user.check_password('password123') is True
        assert user.check_password('wrongpassword') is False

    def test_user_password_validation(self, session):
        """Test password validation."""
        user = User(username='validuser', email='valid@example.com')

        # Test password length validation
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            user.set_password('short')

    def test_user_email_validation(self, session):
        """Test email validation."""
        # Test valid email
        user = User(username='emailuser', email='valid@example.com')
        assert user.email == 'valid@example.com'

        # Test invalid email
        with pytest.raises(ValueError, match="Invalid email format"):
            User(username='invalid', email='invalid-email')

    def test_user_username_validation(self, session):
        """Test username validation."""
        # Test valid username
        user = User(username='valid_user', email='valid@example.com')
        assert user.username == 'valid_user'

        # Test invalid username (too short)
        with pytest.raises(ValueError, match="Username must be 3-80 characters"):
            User(username='ab', email='short@example.com')

        # Test invalid username (invalid characters)
        with pytest.raises(ValueError, match="Username must be 3-80 characters"):
            User(username='invalid@user', email='invalid@example.com')

    def test_user_account_locking(self, session):
        """Test account locking functionality."""
        user = User(username='lockuser', email='lock@example.com')
        user.set_password('password123')
        session.add(user)
        session.commit()

        # Initially account should not be locked
        assert user.is_locked() is False

        # Lock the account
        user.lock_account(duration_minutes=30)
        session.commit()

        # Account should now be locked
        assert user.is_locked() is True
        assert user.failed_login_attempts == 1

        # Set locked_until to the past to simulate time passing
        user.locked_until = datetime.utcnow() - timedelta(minutes=1)
        session.commit()

        # Account should now be unlocked
        assert user.is_locked() is False


class TestAuditLogModel:
    """Test suite for the AuditLog model."""

    def test_audit_log_creation(self, session, test_user):
        """Test creating a new audit log entry."""
        # Create a new audit log entry
        audit_log = AuditLog(
            user_id=test_user.id,
            action='test_action',
            description='Test description',
            success=True,
            ip_address='127.0.0.1',
            details={'test_key': 'test_value'}
        )
        session.add(audit_log)
        session.commit()

        # Retrieve the audit log from the database
        saved_log = AuditLog.query.filter_by(action='test_action').first()

        # Check that audit log was saved correctly
        assert saved_log is not None
        assert saved_log.user_id == test_user.id
        assert saved_log.action == 'test_action'
        assert saved_log.description == 'Test description'
        assert saved_log.success is True
        assert saved_log.ip_address == '127.0.0.1'
        assert saved_log.details.get('test_key') == 'test_value'
        assert saved_log.timestamp is not None

    def test_log_action_class_method(self, session, test_user):
        """Test the log_action class method."""
        # Use the class method to create a log entry
        log_entry = AuditLog.log_action(
            user_id=test_user.id,
            action='class_method_test',
            description='Testing class method',
            resource_type='user',
            resource_id=str(test_user.id),
            success=True,
            error_message=None,
            ip_address='192.168.1.1',
            metadata={'source': 'test'}
        )

        # Check that log entry was created but not committed
        assert log_entry is not None
        assert log_entry.user_id == test_user.id
        assert log_entry.action == 'class_method_test'
        assert log_entry.description == 'Testing class method'
        assert log_entry.resource_type == 'user'
        assert log_entry.resource_id == str(test_user.id)
        assert log_entry.success is True
        assert log_entry.error_message is None
        assert log_entry.ip_address == '192.168.1.1'
        assert log_entry.details.get('source') == 'test'

        # Commit the session to save the log entry
        session.commit()

        # Retrieve the log entry from the database
        saved_log = AuditLog.query.filter_by(action='class_method_test').first()
        assert saved_log is not None
        assert saved_log.id == log_entry.id


class TestAnalysisFileModel:
    """Test suite for the AnalysisFile model."""

    def test_analysis_file_creation(self, session, test_user):
        """Test creating a new analysis file."""
        # Create a new analysis file
        file = AnalysisFile(
            filename='test_file.txt',
            file_size=1024,
            sha256_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            md5_hash='d41d8cd98f00b204e9800998ecf8427e',
            file_type='text',
            mime_type='text/plain',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Retrieve the file from the database
        saved_file = AnalysisFile.query.filter_by(sha256_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').first()

        # Check that file was saved correctly
        assert saved_file is not None
        assert saved_file.filename == 'test_file.txt'
        assert saved_file.file_size == 1024
        assert saved_file.file_type == 'text'
        assert saved_file.mime_type == 'text/plain'
        assert saved_file.created_by == test_user.id
        assert saved_file.status == FileStatus.PENDING.value
        assert saved_file.priority == 5  # Default priority
        assert saved_file.is_root_file is False  # Default value
        assert saved_file.created_at is not None

    def test_filename_validation(self, session, test_user):
        """Test filename validation."""
        # Test valid filename
        file = AnalysisFile(
            filename='valid_file.txt',
            file_size=1024,
            sha256_hash='hash1',
            created_by=test_user.id
        )
        assert file.filename == 'valid_file.txt'

        # Test empty filename
        with pytest.raises(ValueError, match="Filename cannot be empty"):
            AnalysisFile(
                filename='',
                file_size=1024,
                sha256_hash='hash2',
                created_by=test_user.id
            )

        # Test filename sanitization (path traversal)
        file = AnalysisFile(
            filename='../../../etc/passwd',
            file_size=1024,
            sha256_hash='hash3',
            created_by=test_user.id
        )
        assert file.filename == 'passwd'  # Should strip path components

        # Test long filename truncation
        long_name = 'a' * 300
        file = AnalysisFile(
            filename=long_name,
            file_size=1024,
            sha256_hash='hash4',
            created_by=test_user.id
        )
        assert len(file.filename) == 255  # Should truncate to 255 chars

    def test_priority_validation(self, session, test_user):
        """Test priority validation."""
        # Test valid priority
        file = AnalysisFile(
            filename='priority_file.txt',
            file_size=1024,
            sha256_hash='hash5',
            created_by=test_user.id,
            priority=8
        )
        assert file.priority == 8

        # Test invalid priority (too low)
        with pytest.raises(ValueError, match="Priority must be integer between 1-10"):
            AnalysisFile(
                filename='low_priority.txt',
                file_size=1024,
                sha256_hash='hash6',
                created_by=test_user.id,
                priority=0
            )

        # Test invalid priority (too high)
        with pytest.raises(ValueError, match="Priority must be integer between 1-10"):
            AnalysisFile(
                filename='high_priority.txt',
                file_size=1024,
                sha256_hash='hash7',
                created_by=test_user.id,
                priority=11
            )

        # Test invalid priority (non-integer)
        with pytest.raises(ValueError, match="Priority must be integer between 1-10"):
            AnalysisFile(
                filename='float_priority.txt',
                file_size=1024,
                sha256_hash='hash8',
                created_by=test_user.id,
                priority=5.5
            )

    def test_mark_as_analyzed(self, session, test_user):
        """Test marking a file as analyzed."""
        # Create a file
        file = AnalysisFile(
            filename='analyze_me.txt',
            file_size=2048,
            sha256_hash='hash9',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Initially file should be pending
        assert file.status == FileStatus.PENDING.value
        assert file.analyzed_at is None
        assert file.analyzed_by is None

        # Mark as analyzed
        file.mark_as_analyzed(user_id=test_user.id, duration=10.5, cost=0.25)
        session.commit()

        # File should now be marked as analyzed
        assert file.status == FileStatus.COMPLETE
        assert file.analyzed_at is not None
        assert file.analyzed_by == test_user.id
        assert file.analysis_duration == 10.5
        assert file.processing_cost == 0.25

    def test_tag_management(self, session, test_user):
        """Test adding and removing tags."""
        # Create a file
        file = AnalysisFile(
            filename='tagged_file.txt',
            file_size=3072,
            sha256_hash='hash10',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Initially file should have no tags
        assert file.tags == []

        # Add tags
        file.add_tag('important')
        file.add_tag('crypto')
        file.add_tag('review')
        session.commit()

        # Check tags were added
        assert 'important' in file.tags
        assert 'crypto' in file.tags
        assert 'review' in file.tags
        assert len(file.tags) == 3

        # Add duplicate tag (should not add)
        file.add_tag('important')
        session.commit()
        assert len(file.tags) == 3  # Still 3 tags

        # Remove tag
        file.remove_tag('crypto')
        session.commit()
        assert 'crypto' not in file.tags
        assert len(file.tags) == 2

        # Remove non-existent tag (should not error)
        file.remove_tag('nonexistent')
        session.commit()
        assert len(file.tags) == 2  # Still 2 tags

    def test_find_by_methods(self, session, test_user):
        """Test the find_by_sha and find_by_public_id methods."""
        # Create a file
        file = AnalysisFile(
            filename='findable.txt',
            file_size=4096,
            sha256_hash='findme123',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test find_by_sha
        found_file = AnalysisFile.find_by_sha('findme123')
        assert found_file is not None
        assert found_file.id == file.id

        # Test find_by_sha with non-existent hash
        not_found = AnalysisFile.find_by_sha('nonexistent')
        assert not_found is None

        # Test find_by_public_id
        found_by_id = AnalysisFile.find_by_public_id(str(file.public_id))
        assert found_by_id is not None
        assert found_by_id.id == file.id

        # Test find_by_public_id with invalid UUID
        invalid = AnalysisFile.find_by_public_id('not-a-uuid')
        assert invalid is None


class TestFindingModel:
    """Test suite for the Finding model."""

    def test_finding_creation(self, session, test_user):
        """Test creating a new finding."""
        # First create a file to associate with the finding
        file = AnalysisFile(
            filename='file_with_finding.txt',
            file_size=1024,
            sha256_hash='finding_file_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create a finding
        finding = Finding(
            file_id=file.id,
            finding_type='crypto_key',
            category='cryptography',
            title='Found potential encryption key',
            description='A potential encryption key was found in the file',
            byte_offset=128,
            byte_length=32,
            confidence_level=8,
            priority=7,
            severity='high',
            created_by=test_user.id
        )
        session.add(finding)
        session.commit()

        # Retrieve the finding from the database
        saved_finding = Finding.query.filter_by(title='Found potential encryption key').first()

        # Check that finding was saved correctly
        assert saved_finding is not None
        assert saved_finding.file_id == file.id
        assert saved_finding.finding_type == 'crypto_key'
        assert saved_finding.category == 'cryptography'
        assert saved_finding.title == 'Found potential encryption key'
        assert saved_finding.description == 'A potential encryption key was found in the file'
        assert saved_finding.byte_offset == 128
        assert saved_finding.byte_length == 32
        assert saved_finding.confidence_level == 8
        assert saved_finding.priority == 7
        assert saved_finding.severity == 'high'
        assert saved_finding.created_by == test_user.id
        assert saved_finding.status == FindingStatus.UNVERIFIED
        assert saved_finding.created_at is not None
        assert saved_finding.public_id is not None

    def test_confidence_validation(self, session, test_user):
        """Test confidence level validation."""
        # Create a file
        file = AnalysisFile(
            filename='confidence_test.txt',
            file_size=1024,
            sha256_hash='confidence_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test valid confidence level
        finding = Finding(
            file_id=file.id,
            finding_type='test',
            title='Test Finding',
            confidence_level=9,
            created_by=test_user.id
        )
        assert finding.confidence_level == 9

        # Test invalid confidence level (too low)
        with pytest.raises(ValueError, match="Confidence level must be integer between 1-10"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='Low Confidence',
                confidence_level=0,
                created_by=test_user.id
            )

        # Test invalid confidence level (too high)
        with pytest.raises(ValueError, match="Confidence level must be integer between 1-10"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='High Confidence',
                confidence_level=11,
                created_by=test_user.id
            )

        # Test invalid confidence level (non-integer)
        with pytest.raises(ValueError, match="Confidence level must be integer between 1-10"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='Float Confidence',
                confidence_level=7.5,
                created_by=test_user.id
            )

    def test_priority_validation(self, session, test_user):
        """Test priority validation."""
        # Create a file
        file = AnalysisFile(
            filename='priority_test.txt',
            file_size=1024,
            sha256_hash='priority_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test valid priority
        finding = Finding(
            file_id=file.id,
            finding_type='test',
            title='Test Finding',
            priority=6,
            created_by=test_user.id
        )
        assert finding.priority == 6

        # Test invalid priority (too low)
        with pytest.raises(ValueError, match="Priority must be integer between 1-10"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='Low Priority',
                priority=0,
                created_by=test_user.id
            )

        # Test invalid priority (too high)
        with pytest.raises(ValueError, match="Priority must be integer between 1-10"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='High Priority',
                priority=11,
                created_by=test_user.id
            )

    def test_severity_validation(self, session, test_user):
        """Test severity validation."""
        # Create a file
        file = AnalysisFile(
            filename='severity_test.txt',
            file_size=1024,
            sha256_hash='severity_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test valid severities
        valid_severities = ['low', 'medium', 'high', 'critical']
        for severity in valid_severities:
            finding = Finding(
                file_id=file.id,
                finding_type='test',
                title=f'{severity.capitalize()} Severity Finding',
                severity=severity,
                created_by=test_user.id
            )
            assert finding.severity == severity

        # Test invalid severity
        with pytest.raises(ValueError, match="Severity must be one of:"):
            Finding(
                file_id=file.id,
                finding_type='test',
                title='Invalid Severity',
                severity='extreme',
                created_by=test_user.id
            )

    def test_mark_as_confirmed(self, session, test_user, admin_user):
        """Test marking a finding as confirmed."""
        # Create a file
        file = AnalysisFile(
            filename='confirm_test.txt',
            file_size=1024,
            sha256_hash='confirm_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create a finding
        finding = Finding(
            file_id=file.id,
            finding_type='test',
            title='Finding to Confirm',
            created_by=test_user.id
        )
        session.add(finding)
        session.commit()

        # Initially finding should be unverified
        assert finding.status == FindingStatus.UNVERIFIED
        assert finding.validated_by is None
        assert finding.validated_at is None

        # Mark as confirmed
        finding.mark_as_confirmed(user_id=admin_user.id, notes="Verified by admin")
        session.commit()

        # Finding should now be confirmed
        assert finding.status == FindingStatus.CONFIRMED
        assert finding.validated_by == admin_user.id
        assert finding.validated_at is not None
        assert "Verified by admin" in finding.description

    def test_mark_as_false_positive(self, session, test_user, admin_user):
        """Test marking a finding as false positive."""
        # Create a file
        file = AnalysisFile(
            filename='false_positive_test.txt',
            file_size=1024,
            sha256_hash='false_positive_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create a finding
        finding = Finding(
            file_id=file.id,
            finding_type='test',
            title='False Positive Finding',
            created_by=test_user.id
        )
        session.add(finding)
        session.commit()

        # Initially finding should be unverified
        assert finding.status == FindingStatus.UNVERIFIED
        assert finding.validated_by is None
        assert finding.validated_at is None
        assert finding.false_positive_reason is None

        # Mark as false positive
        finding.mark_as_false_positive(user_id=admin_user.id, reason="Pattern matches normal data")
        session.commit()

        # Finding should now be marked as false positive
        assert finding.status == FindingStatus.FALSE_POSITIVE
        assert finding.validated_by == admin_user.id
        assert finding.validated_at is not None
        assert finding.false_positive_reason == "Pattern matches normal data"

    def test_to_dict(self, session, test_user):
        """Test the to_dict method."""
        # Create a file
        file = AnalysisFile(
            filename='dict_test.txt',
            file_size=1024,
            sha256_hash='dict_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create a finding
        finding = Finding(
            file_id=file.id,
            finding_type='test',
            category='test_category',
            title='Dict Test Finding',
            description='Testing to_dict method',
            byte_offset=256,
            byte_length=64,
            context='Some context around the finding',
            evidence_data={'key': 'value'},
            analysis_method='test_method',
            created_by=test_user.id
        )
        session.add(finding)
        session.commit()

        # Get dictionary representation
        finding_dict = finding.to_dict()

        # Check dictionary values
        assert finding_dict['id'] == finding.public_id.hex
        assert finding_dict['finding_type'] == 'test'
        assert finding_dict['category'] == 'test_category'
        assert finding_dict['title'] == 'Dict Test Finding'
        assert finding_dict['description'] == 'Testing to_dict method'
        assert finding_dict['status'] == 'unverified'
        assert finding_dict['byte_offset'] == 256
        assert finding_dict['byte_length'] == 64
        assert finding_dict['context'] == 'Some context around the finding'
        assert finding_dict['evidence_data'] == {'key': 'value'}
        assert finding_dict['analysis_method'] == 'test_method'
        assert finding_dict['creator'] == test_user.username


class TestFileContentModel:
    """Test suite for the FileContent model."""

    def test_file_content_creation(self, session, test_user):
        """Test creating new file content."""
        # First create a file to associate with the content
        file = AnalysisFile(
            filename='content_test.txt',
            file_size=1024,
            sha256_hash='content_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create file content
        content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_format='text',
            encoding='utf-8',
            content_text='This is test content for the file',
            content_size=len('This is test content for the file'),
            extracted_by=test_user.id,
            extraction_method='manual'
        )
        session.add(content)
        session.commit()

        # Retrieve the content from the database
        saved_content = FileContent.query.filter_by(file_id=file.id).first()

        # Check that content was saved correctly
        assert saved_content is not None
        assert saved_content.file_id == file.id
        assert saved_content.content_type == 'extracted_text'
        assert saved_content.content_format == 'text'
        assert saved_content.encoding == 'utf-8'
        assert saved_content.content_text == 'This is test content for the file'
        assert saved_content.content_size == len('This is test content for the file')
        assert saved_content.extracted_by == test_user.id
        assert saved_content.extraction_method == 'manual'
        assert saved_content.extracted_at is not None

    def test_content_type_validation(self, session, test_user):
        """Test content type validation."""
        # Create a file
        file = AnalysisFile(
            filename='type_validation.txt',
            file_size=1024,
            sha256_hash='type_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test valid content types
        valid_types = [
            'raw_binary', 'extracted_text', 'hex_dump', 'strings_output',
            'crypto_analysis', 'llm_analysis', 'metadata', 'exif_data',
            'archive_listing', 'disassembly', 'network_data', 'registry_data',
            'advanced_zsteg_analysis', 'binwalk_results'
        ]

        for content_type in valid_types:
            content = FileContent(
                file_id=file.id,
                content_type=content_type,
                content_text='Test content',
                content_size=len('Test content')
            )
            assert content.content_type == content_type

        # Test invalid content type
        with pytest.raises(ValueError, match="Invalid content type"):
            FileContent(
                file_id=file.id,
                content_type='invalid_type',
                content_text='Test content',
                content_size=len('Test content')
            )

    def test_get_content_method(self, session, test_user):
        """Test the get_content method."""
        # Create a file
        file = AnalysisFile(
            filename='get_content_test.txt',
            file_size=1024,
            sha256_hash='get_content_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Test text content
        text_content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_format='text',
            content_text='This is text content',
            content_size=len('This is text content')
        )
        session.add(text_content)

        # Test binary content
        binary_content = FileContent(
            file_id=file.id,
            content_type='raw_binary',
            content_format='binary',
            content_bytes=b'This is binary content',
            content_size=len(b'This is binary content')
        )
        session.add(binary_content)

        # Test JSON content
        json_content = FileContent(
            file_id=file.id,
            content_type='metadata',
            content_format='json',
            content_json={'key': 'value', 'nested': {'data': True}},
            content_size=len(str({'key': 'value', 'nested': {'data': True}}))
        )
        session.add(json_content)
        session.commit()

        # Test get_content for text
        assert text_content.get_content() == 'This is text content'

        # Test get_content for binary
        assert text_content.get_content() == 'This is text content'

        # Test get_content for JSON
        assert json_content.get_content() == {'key': 'value', 'nested': {'data': True}}

    def test_set_content_method(self, session, test_user):
        """Test the set_content method."""
        # Create a file
        file = AnalysisFile(
            filename='set_content_test.txt',
            file_size=1024,
            sha256_hash='set_content_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        # Create empty content
        content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_size=0
        )
        session.add(content)
        session.commit()

        # Test setting text content
        content.set_content("This is new text content")
        session.commit()
        assert content.content_text == "This is new text content"
        assert content.content_format == "text"
        assert content.content_size == len("This is new text content")
        assert content.checksum is not None

        # Test setting binary content
        content.set_content(b"This is binary content")
        session.commit()
        assert content.content_bytes == b"This is binary content"
        assert content.content_format == "binary"
        assert content.content_size == len(b"This is binary content")
        assert content.checksum is not None

        # Test setting JSON content
        json_data = {"key": "value", "list": [1, 2, 3]}
        content.set_content(json_data)
        session.commit()
        assert content.content_json == json_data
        assert content.content_format == "json"
        assert content.content_size == len(str(json_data))
        assert content.checksum is not None


class TestRegionOfInterestModel:
    """Test suite for the RegionOfInterest model."""

    def test_region_creation(self, session, test_user):
        """Test creating a new region of interest."""
        # First create a file and file content
        file = AnalysisFile(
            filename='region_test.txt',
            file_size=1024,
            sha256_hash='region_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_text='This is a test file with some interesting content that contains a secret: 1a2b3c4d5e6f',
            content_size=len('This is a test file with some interesting content that contains a secret: 1a2b3c4d5e6f')
        )
        session.add(content)
        session.commit()

        # Create a region of interest
        region = RegionOfInterest(
            file_content_id=content.id,
            start_offset=57,  # Start of "secret: 1a2b3c4d5e6f"
            end_offset=75,    # End of "secret: 1a2b3c4d5e6f"
            title='Potential Secret Key',
            description='Hexadecimal pattern that might be a secret key',
            region_type='crypto',
            color='#ffff00',  # Yellow
            highlight_style='background',
            confidence_score=0.85,
            importance_level=4,
            created_by=test_user.id,
            extra_data={'pattern_type': 'hex', 'entropy': 3.2}
        )
        session.add(region)
        session.commit()

        # Retrieve the region from the database
        saved_region = RegionOfInterest.query.filter_by(title='Potential Secret Key').first()

        # Check that region was saved correctly
        assert saved_region is not None
        assert saved_region.file_content_id == content.id
        assert saved_region.start_offset == 57
        assert saved_region.end_offset == 75
        assert saved_region.title == 'Potential Secret Key'
        assert saved_region.description == 'Hexadecimal pattern that might be a secret key'
        assert saved_region.region_type == 'crypto'
        assert saved_region.color == '#ffff00'
        assert saved_region.highlight_style == 'background'
        assert saved_region.confidence_score == 0.85
        assert saved_region.importance_level == 4
        assert saved_region.created_by == test_user.id
        assert saved_region.extra_data['pattern_type'] == 'hex'
        assert saved_region.extra_data['entropy'] == 3.2
        assert saved_region.created_at is not None
        assert saved_region.public_id is not None

    def test_region_boundaries(self, session, test_user):
        """Test region boundary validation."""
        # Create file and content
        file = AnalysisFile(
            filename='boundary_test.txt',
            file_size=1024,
            sha256_hash='boundary_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_text='Short text',
            content_size=len('Short text')
        )
        session.add(content)
        session.commit()

        # Test valid boundaries
        region = RegionOfInterest(
            file_content_id=content.id,
            start_offset=0,
            end_offset=9,  # Length of 'Short text'
            title='Full Text',
            region_type='text'
        )
        assert region.start_offset == 0
        assert region.end_offset == 9

        # Test partial text
        region = RegionOfInterest(
            file_content_id=content.id,
            start_offset=6,
            end_offset=9,  # Just 'text'
            title='Partial Text',
            region_type='text'
        )
        assert region.start_offset == 6
        assert region.end_offset == 9

        # Test single character
        region = RegionOfInterest(
            file_content_id=content.id,
            start_offset=0,
            end_offset=1,  # Just 'S'
            title='Single Character',
            region_type='text'
        )
        assert region.start_offset == 0
        assert region.end_offset == 1

    def test_region_with_extra_data(self, session, test_user):
        """Test region with complex extra data."""
        # Create file and content
        file = AnalysisFile(
            filename='extra_data_test.txt',
            file_size=1024,
            sha256_hash='extra_data_hash',
            created_by=test_user.id
        )
        session.add(file)
        session.commit()

        content = FileContent(
            file_id=file.id,
            content_type='extracted_text',
            content_text='Test content',
            content_size=len('Test content')
        )
        session.add(content)
        session.commit()

        # Create region with complex extra data
        complex_data = {
            'analysis_results': {
                'entropy': 4.2,
                'character_distribution': {'a': 0.1, 'b': 0.2, 'c': 0.3},
                'patterns': ['hex', 'base64']
            },
            'ai_analysis': {
                'confidence': 0.92,
                'model_used': 'gpt-4',
                'classification': 'encryption_key',
                'similar_findings': [
                    {'id': 'abc123', 'similarity': 0.85},
                    {'id': 'def456', 'similarity': 0.72}
                ]
            },
            'metadata': {
                'created_by_tool': 'advanced_analyzer_v2',
                'timestamp': '2025-06-15T12:34:56Z',
                'tags': ['important', 'review', 'encryption']
            }
        }

        region = RegionOfInterest(
            file_content_id=content.id,
            start_offset=0,
            end_offset=12,
            title='Complex Data Test',
            region_type='crypto',
            extra_data=complex_data
        )
        session.add(region)
        session.commit()

        # Retrieve the region
        saved_region = RegionOfInterest.query.filter_by(title='Complex Data Test').first()

        # Check that complex data was saved correctly
        assert saved_region is not None
        assert saved_region.extra_data == complex_data
        assert saved_region.extra_data['analysis_results']['entropy'] == 4.2
        assert saved_region.extra_data['ai_analysis']['model_used'] == 'gpt-4'
        assert 'encryption' in saved_region.extra_data['metadata']['tags']
        assert len(saved_region.extra_data['ai_analysis']['similar_findings']) == 2
