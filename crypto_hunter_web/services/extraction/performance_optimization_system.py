#!/usr/bin/env python3
"""
Performance Optimization System for Crypto Hunter
================================================

Handles hundreds of thousands of files efficiently with:
- Intelligent task scheduling and prioritization
- Parallel processing with resource management
- Memory-efficient file handling
- Database connection pooling and batch operations
- Intelligent caching and deduplication
- Progress monitoring and ETA calculation
- Storage optimization and cleanup
- Recovery from interruptions

Critical for handling massive steganography extractions.
"""

import os
import sys
import threading
import multiprocessing
import queue
import time
import psutil
import sqlite3
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
import logging
import json
import hashlib
from datetime import datetime, timedelta
import weakref
import gc
from contextlib import contextmanager

# Add project path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

@dataclass
class SystemResources:
    """Track system resource usage"""
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    available_memory: int
    available_disk: int
    load_average: float
    io_wait: float

@dataclass
class ExtractionMetrics:
    """Track extraction performance metrics"""
    files_processed: int = 0
    files_extracted: int = 0
    bytes_processed: int = 0
    bytes_extracted: int = 0
    processing_time: float = 0.0
    errors: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    start_time: Optional[datetime] = None
    last_update: Optional[datetime] = None

class ResourceMonitor:
    """Monitor system resources and adjust processing accordingly"""
    
    def __init__(self):
        self.cpu_threshold = 85.0  # Max CPU usage %
        self.memory_threshold = 80.0  # Max memory usage %
        self.disk_threshold = 90.0  # Max disk usage %
        self.monitoring = False
        self.monitor_thread = None
        self.current_resources = None
        self.callbacks = []
    
    def start_monitoring(self, interval: float = 1.0):
        """Start resource monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Resource monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        logger.info("Resource monitoring stopped")
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Get current system stats
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                load_avg = os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0
                
                # Calculate IO wait if available
                io_wait = 0.0
                try:
                    io_stats = psutil.cpu_times_percent(interval=0.1)
                    io_wait = getattr(io_stats, 'iowait', 0.0)
                except:
                    pass
                
                self.current_resources = SystemResources(
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    disk_usage_percent=disk.percent,
                    available_memory=memory.available,
                    available_disk=disk.free,
                    load_average=load_avg,
                    io_wait=io_wait
                )
                
                # Notify callbacks
                for callback in self.callbacks:
                    try:
                        callback(self.current_resources)
                    except Exception as e:
                        logger.warning(f"Resource monitor callback failed: {e}")
                
                time.sleep(interval)
            
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                time.sleep(interval)
    
    def add_callback(self, callback):
        """Add resource change callback"""
        self.callbacks.append(callback)
    
    def is_overloaded(self) -> bool:
        """Check if system is overloaded"""
        if not self.current_resources:
            return False
        
        return (
            self.current_resources.cpu_percent > self.cpu_threshold or
            self.current_resources.memory_percent > self.memory_threshold or
            self.current_resources.disk_usage_percent > self.disk_threshold
        )
    
    def get_optimal_worker_count(self) -> int:
        """Calculate optimal worker count based on resources"""
        if not self.current_resources:
            return multiprocessing.cpu_count()
        
        # Base worker count on CPU cores
        base_workers = multiprocessing.cpu_count()
        
        # Adjust based on current load
        if self.current_resources.cpu_percent > 70:
            base_workers = max(1, base_workers // 2)
        elif self.current_resources.memory_percent > 70:
            base_workers = max(1, base_workers // 2)
        
        return base_workers

class IntelligentFileCache:
    """Intelligent caching system for file operations"""
    
    def __init__(self, max_size: int = 1000000, max_memory: int = 512*1024*1024):
        self.max_size = max_size  # Max number of entries
        self.max_memory = max_memory  # Max memory usage in bytes
        self.cache = {}
        self.access_times = {}
        self.memory_usage = 0
        self.cache_lock = threading.RLock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self.cache_lock:
            if key in self.cache:
                self.access_times[key] = time.time()
                self.hits += 1
                return self.cache[key]
            else:
                self.misses += 1
                return None
    
    def put(self, key: str, value: Any, size: int = None):
        """Put item in cache"""
        if size is None:
            size = sys.getsizeof(value)
        
        with self.cache_lock:
            # Check if we need to evict items
            while (len(self.cache) >= self.max_size or 
                   self.memory_usage + size > self.max_memory):
                self._evict_lru()
            
            # Add new item
            self.cache[key] = value
            self.access_times[key] = time.time()
            self.memory_usage += size
    
    def _evict_lru(self):
        """Evict least recently used item"""
        if not self.cache:
            return
        
        # Find LRU item
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        
        # Remove it
        value = self.cache.pop(lru_key)
        del self.access_times[lru_key]
        self.memory_usage -= sys.getsizeof(value)
    
    def clear(self):
        """Clear cache"""
        with self.cache_lock:
            self.cache.clear()
            self.access_times.clear()
            self.memory_usage = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.cache_lock:
            total_requests = self.hits + self.misses
            hit_rate = self.hits / total_requests if total_requests > 0 else 0.0
            
            return {
                'size': len(self.cache),
                'memory_usage': self.memory_usage,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'max_size': self.max_size,
                'max_memory': self.max_memory
            }

class BatchDatabaseManager:
    """Efficient batch database operations for massive datasets"""
    
    def __init__(self, db_path: str = None, batch_size: int = 1000):
        self.db_path = db_path or 'crypto_hunter.db'
        self.batch_size = batch_size
        self.pending_inserts = {}
        self.pending_updates = {}
        self.db_lock = threading.RLock()
        self.connection_pool = queue.Queue(maxsize=10)
        self.metrics = ExtractionMetrics()
        
        # Initialize connection pool
        for _ in range(5):
            conn = self._create_connection()
            if conn:
                self.connection_pool.put(conn)
    
    def _create_connection(self):
        """Create database connection with optimizations"""
        try:
            conn = sqlite3.connect(
                self.db_path,
                isolation_level=None,  # Autocommit mode
                check_same_thread=False
            )
            
            # Optimize for bulk operations
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=-64000')  # 64MB cache
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.execute('PRAGMA mmap_size=268435456')  # 256MB mmap
            
            return conn
        except Exception as e:
            logger.error(f"Failed to create database connection: {e}")
            return None
    
    @contextmanager
    def get_connection(self):
        """Get connection from pool"""
        conn = None
        try:
            conn = self.connection_pool.get(timeout=5.0)
            yield conn
        except queue.Empty:
            # Create temporary connection if pool exhausted
            conn = self._create_connection()
            yield conn
        finally:
            if conn:
                try:
                    self.connection_pool.put_nowait(conn)
                except queue.Full:
                    conn.close()
    
    def queue_insert(self, table: str, data: Dict[str, Any]):
        """Queue an insert operation"""
        with self.db_lock:
            if table not in self.pending_inserts:
                self.pending_inserts[table] = []
            
            self.pending_inserts[table].append(data)
            
            # Auto-flush if batch size reached
            if len(self.pending_inserts[table]) >= self.batch_size:
                self._flush_inserts(table)
    
    def queue_update(self, table: str, data: Dict[str, Any], where_clause: str):
        """Queue an update operation"""
        with self.db_lock:
            key = f"{table}:{where_clause}"
            if key not in self.pending_updates:
                self.pending_updates[key] = []
            
            self.pending_updates[key].append(data)
            
            # Auto-flush if batch size reached
            if len(self.pending_updates[key]) >= self.batch_size:
                self._flush_updates(key, table, where_clause)
    
    def _flush_inserts(self, table: str):
        """Flush pending inserts for a table"""
        if table not in self.pending_inserts or not self.pending_inserts[table]:
            return
        
        data_list = self.pending_inserts[table]
        self.pending_inserts[table] = []
        
        try:
            with self.get_connection() as conn:
                # Build insert query
                if not data_list:
                    return
                
                columns = list(data_list[0].keys())
                placeholders = ', '.join(['?' * len(columns)])
                query = f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
                
                # Convert data to tuples
                values = []
                for data in data_list:
                    values.append(tuple(data[col] for col in columns))
                
                # Execute batch insert
                conn.executemany(query, values)
                
                logger.debug(f"Batch inserted {len(values)} records into {table}")
        
        except Exception as e:
            logger.error(f"Batch insert failed for {table}: {e}")
            # Re-queue failed data
            with self.db_lock:
                self.pending_inserts[table].extend(data_list)
    
    def _flush_updates(self, key: str, table: str, where_clause: str):
        """Flush pending updates"""
        if key not in self.pending_updates or not self.pending_updates[key]:
            return
        
        data_list = self.pending_updates[key]
        self.pending_updates[key] = []
        
        try:
            with self.get_connection() as conn:
                for data in data_list:
                    # Build update query
                    set_clause = ', '.join([f"{col} = ?" for col in data.keys()])
                    query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
                    
                    conn.execute(query, list(data.values()))
                
                logger.debug(f"Batch updated {len(data_list)} records in {table}")
        
        except Exception as e:
            logger.error(f"Batch update failed for {table}: {e}")
            # Re-queue failed data
            with self.db_lock:
                self.pending_updates[key].extend(data_list)
    
    def flush_all(self):
        """Flush all pending operations"""
        with self.db_lock:
            # Flush inserts
            for table in list(self.pending_inserts.keys()):
                self._flush_inserts(table)
            
            # Flush updates
            for key in list(self.pending_updates.keys()):
                parts = key.split(':', 1)
                if len(parts) == 2:
                    table, where_clause = parts
                    self._flush_updates(key, table, where_clause)
    
    def close(self):
        """Close database manager"""
        self.flush_all()
        
        # Close all connections
        while not self.connection_pool.empty():
            try:
                conn = self.connection_pool.get_nowait()
                conn.close()
            except queue.Empty:
                break

class SmartDeduplicationSystem:
    """Intelligent deduplication using multiple strategies"""
    
    def __init__(self, cache_size: int = 100000):
        self.hash_cache = IntelligentFileCache(max_size=cache_size)
        self.content_signatures = {}
        self.fuzzy_hashes = {}
        self.processed_files = set()
        self.duplicate_groups = []
        self.dedup_lock = threading.RLock()
    
    def calculate_file_signature(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple file signatures for deduplication"""
        signatures = {}
        
        try:
            # Check cache first
            cache_key = f"sig:{file_path}:{os.path.getmtime(file_path)}"
            cached = self.hash_cache.get(cache_key)
            if cached:
                return cached
            
            with open(file_path, 'rb') as f:
                # Read file in chunks for memory efficiency
                sha256_hash = hashlib.sha256()
                md5_hash = hashlib.md5()
                first_chunk = None
                last_chunk = None
                file_size = 0
                
                chunk_size = 65536  # 64KB chunks
                chunk_count = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    file_size += len(chunk)
                    
                    # Store first and last chunks for similarity analysis
                    if chunk_count == 0:
                        first_chunk = chunk
                    last_chunk = chunk
                    chunk_count += 1
                    
                    # Limit processing for very large files
                    if chunk_count > 1000:  # ~64MB processed
                        break
                
                signatures = {
                    'sha256': sha256_hash.hexdigest(),
                    'md5': md5_hash.hexdigest(),
                    'size': file_size,
                    'first_1kb': hashlib.sha256(first_chunk[:1024] if first_chunk else b'').hexdigest(),
                    'last_1kb': hashlib.sha256(last_chunk[-1024:] if last_chunk else b'').hexdigest(),
                }
                
                # Add to cache
                self.hash_cache.put(cache_key, signatures)
        
        except Exception as e:
            logger.warning(f"Failed to calculate signatures for {file_path}: {e}")
            signatures = {'error': str(e)}
        
        return signatures
    
    def is_duplicate(self, file_path: str, signatures: Dict[str, str] = None) -> Tuple[bool, Optional[str]]:
        """Check if file is a duplicate"""
        if not signatures:
            signatures = self.calculate_file_signature(file_path)
        
        if 'error' in signatures:
            return False, None
        
        sha256 = signatures.get('sha256')
        if not sha256:
            return False, None
        
        with self.dedup_lock:
            # Exact match check
            if sha256 in self.content_signatures:
                return True, self.content_signatures[sha256]
            
            # Store signature
            self.content_signatures[sha256] = file_path
            
            # Check for similar files (same size, similar first/last chunks)
            size = signatures.get('size', 0)
            first_1kb = signatures.get('first_1kb', '')
            last_1kb = signatures.get('last_1kb', '')
            
            for existing_sha256, existing_path in self.content_signatures.items():
                if existing_sha256 == sha256:
                    continue
                
                existing_sigs = self.calculate_file_signature(existing_path)
                if 'error' in existing_sigs:
                    continue
                
                # Check for near-duplicates
                if (existing_sigs.get('size') == size and
                    existing_sigs.get('first_1kb') == first_1kb and
                    existing_sigs.get('last_1kb') == last_1kb):
                    
                    # Potential near-duplicate found
                    logger.info(f"Near-duplicate detected: {file_path} ~= {existing_path}")
                    return True, existing_path
        
        return False, None
    
    def add_to_duplicate_group(self, original_path: str, duplicate_path: str):
        """Add files to duplicate group"""
        with self.dedup_lock:
            # Find existing group or create new one
            for group in self.duplicate_groups:
                if original_path in group or duplicate_path in group:
                    group.add(original_path)
                    group.add(duplicate_path)
                    return
            
            # Create new group
            self.duplicate_groups.append({original_path, duplicate_path})
    
    def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        with self.dedup_lock:
            total_groups = len(self.duplicate_groups)
            total_duplicates = sum(len(group) - 1 for group in self.duplicate_groups)
            
            return {
                'unique_files': len(self.content_signatures),
                'duplicate_groups': total_groups,
                'total_duplicates': total_duplicates,
                'space_saved_estimate': total_duplicates * 1024 * 1024,  # Rough estimate
                'cache_stats': self.hash_cache.get_stats()
            }

class ProgressTracker:
    """Advanced progress tracking with ETA calculation"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.last_update = self.start_time
        self.total_files = 0
        self.processed_files = 0
        self.extracted_files = 0
        self.current_file = ""
        self.processing_rates = []
        self.max_rate_samples = 100
        self.lock = threading.Lock()
    
    def set_total_files(self, total: int):
        """Set total number of files to process"""
        with self.lock:
            self.total_files = total
    
    def update_progress(self, processed: int = None, extracted: int = None, current_file: str = None):
        """Update progress counters"""
        with self.lock:
            now = datetime.now()
            
            if processed is not None:
                # Calculate processing rate
                time_diff = (now - self.last_update).total_seconds()
                if time_diff > 0:
                    files_diff = processed - self.processed_files
                    rate = files_diff / time_diff
                    
                    self.processing_rates.append(rate)
                    if len(self.processing_rates) > self.max_rate_samples:
                        self.processing_rates.pop(0)
                
                self.processed_files = processed
            
            if extracted is not None:
                self.extracted_files = extracted
            
            if current_file is not None:
                self.current_file = current_file
            
            self.last_update = now
    
    def get_eta(self) -> Optional[timedelta]:
        """Calculate estimated time of arrival"""
        with self.lock:
            if self.total_files <= 0 or self.processed_files <= 0:
                return None
            
            remaining_files = self.total_files - self.processed_files
            if remaining_files <= 0:
                return timedelta(0)
            
            # Use average processing rate
            if not self.processing_rates:
                return None
            
            avg_rate = sum(self.processing_rates) / len(self.processing_rates)
            if avg_rate <= 0:
                return None
            
            eta_seconds = remaining_files / avg_rate
            return timedelta(seconds=eta_seconds)
    
    def get_progress_info(self) -> Dict[str, Any]:
        """Get comprehensive progress information"""
        with self.lock:
            elapsed = datetime.now() - self.start_time
            eta = self.get_eta()
            
            # Calculate rates
            avg_rate = 0.0
            current_rate = 0.0
            
            if self.processing_rates:
                avg_rate = sum(self.processing_rates) / len(self.processing_rates)
                if len(self.processing_rates) >= 5:
                    current_rate = sum(self.processing_rates[-5:]) / 5
            
            # Calculate percentages
            progress_percent = 0.0
            if self.total_files > 0:
                progress_percent = (self.processed_files / self.total_files) * 100
            
            return {
                'total_files': self.total_files,
                'processed_files': self.processed_files,
                'extracted_files': self.extracted_files,
                'progress_percent': progress_percent,
                'current_file': self.current_file,
                'elapsed_time': str(elapsed),
                'eta': str(eta) if eta else 'Unknown',
                'avg_rate_files_per_sec': avg_rate,
                'current_rate_files_per_sec': current_rate,
                'start_time': self.start_time.isoformat(),
                'last_update': self.last_update.isoformat()
            }

class OptimizedExtractionOrchestrator:
    """Main orchestrator for optimized extraction with all performance enhancements"""
    
    def __init__(self, 
                 max_workers: int = None,
                 max_memory_mb: int = 2048,
                 cache_size: int = 100000,
                 batch_size: int = 1000):
        
        # Initialize components
        self.resource_monitor = ResourceMonitor()
        self.file_cache = IntelligentFileCache(max_size=cache_size, max_memory=max_memory_mb*1024*1024)
        self.db_manager = BatchDatabaseManager(batch_size=batch_size)
        self.deduplication = SmartDeduplicationSystem(cache_size=cache_size)
        self.progress_tracker = ProgressTracker()
        
        # Worker management
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.current_workers = 0
        self.worker_lock = threading.Lock()
        
        # Task queue with priority
        self.task_queue = queue.PriorityQueue()
        self.result_queue = queue.Queue()
        
        # Control flags
        self.running = False
        self.paused = False
        
        # Statistics
        self.stats = ExtractionMetrics()
        self.stats.start_time = datetime.now()
        
        # Setup resource monitoring callbacks
        self.resource_monitor.add_callback(self._handle_resource_change)
    
    def start_extraction(self, root_file: str, output_dir: str) -> Dict[str, Any]:
        """Start optimized extraction process"""
        logger.info(f"Starting optimized extraction: {root_file}")
        
        self.running = True
        self.stats.start_time = datetime.now()
        
        # Start resource monitoring
        self.resource_monitor.start_monitoring()
        
        try:
            # Initial file analysis
            self._analyze_initial_file(root_file)
            
            # Start worker threads
            self._start_workers(output_dir)
            
            # Process results
            self._process_results()
            
            # Generate final report
            return self._generate_final_report()
        
        finally:
            self.running = False
            self.resource_monitor.stop_monitoring()
            self.db_manager.close()
    
    def _analyze_initial_file(self, file_path: str):
        """Analyze initial file and estimate total work"""
        try:
            # Calculate file signature
            signatures = self.deduplication.calculate_file_signature(file_path)
            
            # Estimate total files (rough heuristic)
            file_size = signatures.get('size', 0)
            estimated_total = max(100, file_size // (1024 * 1024))  # Rough estimate
            
            self.progress_tracker.set_total_files(estimated_total)
            
            # Queue initial task
            from comprehensive_extractor_system import ExtractionTask, ExtractionPriority, FileCategory
            task = ExtractionTask(
                file_path=file_path,
                file_hash=signatures.get('sha256', ''),
                file_type='application/octet-stream',
                file_size=file_size,
                category=FileCategory.UNKNOWN,
                priority=ExtractionPriority.CRITICAL
            )
            
            self.task_queue.put((task.priority.value, time.time(), task))
            
        except Exception as e:
            logger.error(f"Initial file analysis failed: {e}")
    
    def _start_workers(self, output_dir: str):
        """Start worker threads for processing"""
        optimal_workers = self.resource_monitor.get_optimal_worker_count()
        actual_workers = min(self.max_workers, optimal_workers)
        
        logger.info(f"Starting {actual_workers} worker threads")
        
        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            futures = []
            
            while self.running:
                try:
                    # Check if we should adjust worker count
                    if self.resource_monitor.is_overloaded():
                        logger.warning("System overloaded, reducing workers")
                        time.sleep(2.0)
                        continue
                    
                    # Get next task
                    try:
                        _, _, task = self.task_queue.get(timeout=1.0)
                    except queue.Empty:
                        continue
                    
                    # Check for duplicates
                    is_dup, original_path = self.deduplication.is_duplicate(task.file_path)
                    if is_dup:
                        logger.debug(f"Skipping duplicate: {task.file_path}")
                        self.deduplication.add_to_duplicate_group(original_path, task.file_path)
                        continue
                    
                    # Submit task
                    future = executor.submit(self._process_single_task, task, output_dir)
                    futures.append(future)
                    
                    # Clean up completed futures
                    completed = [f for f in futures if f.done()]
                    for f in completed:
                        futures.remove(f)
                        try:
                            result = f.result()
                            self.result_queue.put(result)
                        except Exception as e:
                            logger.error(f"Task processing failed: {e}")
                            self.stats.errors += 1
                
                except KeyboardInterrupt:
                    logger.info("Extraction interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Worker management error: {e}")
    
    def _process_single_task(self, task, output_dir: str) -> Dict[str, Any]:
        """Process a single extraction task"""
        try:
            # Update progress
            self.progress_tracker.update_progress(
                processed=self.stats.files_processed + 1,
                current_file=os.path.basename(task.file_path)
            )
            
            # Import extraction system
            from comprehensive_extractor_system import ComprehensiveExtractorSystem
            
            extractor = ComprehensiveExtractorSystem(max_workers=1, max_depth=5)
            result = extractor._process_single_file(task, output_dir)
            
            # Update statistics
            self.stats.files_processed += 1
            self.stats.bytes_processed += task.file_size
            
            if result.get('extracted_files'):
                self.stats.files_extracted += len(result['extracted_files'])
                # Queue extracted files
                self._queue_extracted_files(result['extracted_files'], task)
            
            # Store in database
            self._store_task_result(task, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Task processing failed: {e}")
            self.stats.errors += 1
            return {'error': str(e), 'task': task}
    
    def _queue_extracted_files(self, extracted_files: List[str], parent_task):
        """Queue extracted files for further processing"""
        for file_path in extracted_files:
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                try:
                    # Create new task
                    signatures = self.deduplication.calculate_file_signature(file_path)
                    
                    from comprehensive_extractor_system import ExtractionTask, ExtractionPriority, FileCategory
                    task = ExtractionTask(
                        file_path=file_path,
                        file_hash=signatures.get('sha256', ''),
                        file_type='application/octet-stream',
                        file_size=signatures.get('size', 0),
                        category=FileCategory.UNKNOWN,
                        priority=ExtractionPriority.MEDIUM,
                        depth=parent_task.depth + 1,
                        parent_hash=parent_task.file_hash
                    )
                    
                    self.task_queue.put((task.priority.value, time.time(), task))
                    
                except Exception as e:
                    logger.warning(f"Failed to queue extracted file {file_path}: {e}")
    
    def _store_task_result(self, task, result: Dict[str, Any]):
        """Store task result in database"""
        try:
            # Store file record
            file_data = {
                'file_path': task.file_path,
                'file_hash': task.file_hash,
                'file_size': task.file_size,
                'file_type': task.file_type,
                'category': task.category.value,
                'priority': task.priority.value,
                'depth': task.depth,
                'parent_hash': task.parent_hash,
                'processed_at': datetime.now().isoformat(),
                'success': not bool(result.get('error')),
                'error_message': result.get('error', ''),
                'extracted_count': len(result.get('extracted_files', [])),
                'processing_time': result.get('processing_time', 0.0)
            }
            
            self.db_manager.queue_insert('extraction_tasks', file_data)
            
            # Store extracted files
            for extracted_file in result.get('extracted_files', []):
                extracted_data = {
                    'parent_hash': task.file_hash,
                    'extracted_path': extracted_file,
                    'extraction_method': result.get('method', 'unknown'),
                    'created_at': datetime.now().isoformat()
                }
                self.db_manager.queue_insert('extracted_files', extracted_data)
        
        except Exception as e:
            logger.warning(f"Failed to store task result: {e}")
    
    def _process_results(self):
        """Process extraction results"""
        while self.running:
            try:
                result = self.result_queue.get(timeout=1.0)
                
                # Update progress tracker
                self.progress_tracker.update_progress(
                    extracted=self.stats.files_extracted
                )
                
                # Log progress periodically
                if self.stats.files_processed % 100 == 0:
                    progress_info = self.progress_tracker.get_progress_info()
                    logger.info(f"Progress: {progress_info['progress_percent']:.1f}% "
                              f"({progress_info['processed_files']}/{progress_info['total_files']}) "
                              f"ETA: {progress_info['eta']}")
            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Result processing error: {e}")
    
    def _handle_resource_change(self, resources: SystemResources):
        """Handle resource changes"""
        # Adjust worker count based on resources
        if resources.memory_percent > 85:
            logger.warning(f"High memory usage: {resources.memory_percent:.1f}%")
            # Could pause processing or reduce workers
        
        if resources.cpu_percent > 90:
            logger.warning(f"High CPU usage: {resources.cpu_percent:.1f}%")
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report"""
        end_time = datetime.now()
        duration = end_time - self.stats.start_time
        
        # Get final statistics
        progress_info = self.progress_tracker.get_progress_info()
        dedup_stats = self.deduplication.get_deduplication_stats()
        cache_stats = self.file_cache.get_stats()
        
        return {
            'extraction_summary': {
                'start_time': self.stats.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': str(duration),
                'files_processed': self.stats.files_processed,
                'files_extracted': self.stats.files_extracted,
                'bytes_processed': self.stats.bytes_processed,
                'bytes_extracted': self.stats.bytes_extracted,
                'errors': self.stats.errors,
                'success_rate': (self.stats.files_extracted / max(self.stats.files_processed, 1)) * 100
            },
            'performance_metrics': {
                'avg_files_per_second': self.stats.files_processed / duration.total_seconds(),
                'avg_bytes_per_second': self.stats.bytes_processed / duration.total_seconds(),
                'cache_hit_rate': cache_stats['hit_rate'],
                'memory_efficiency': cache_stats['memory_usage'] / cache_stats['max_memory']
            },
            'deduplication_stats': dedup_stats,
            'progress_info': progress_info,
            'cache_stats': cache_stats
        }

def main():
    """Main function for testing the optimization system"""
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    orchestrator = OptimizedExtractionOrchestrator(
        max_workers=8,
        max_memory_mb=2048,
        cache_size=50000,
        batch_size=500
    )
    
    input_file = sys.argv[1] if len(sys.argv) > 1 else "test_image.png"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./optimized_output"
    
    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        return 1
    
    # Run extraction
    try:
        report = orchestrator.start_extraction(input_file, output_dir)
        
        # Print summary
        print("\n" + "="*50)
        print("EXTRACTION COMPLETED")
        print("="*50)
        
        summary = report['extraction_summary']
        print(f"Duration: {summary['duration']}")
        print(f"Files processed: {summary['files_processed']:,}")
        print(f"Files extracted: {summary['files_extracted']:,}")
        print(f"Success rate: {summary['success_rate']:.1f}%")
        print(f"Errors: {summary['errors']}")
        
        perf = report['performance_metrics']
        print(f"Processing rate: {perf['avg_files_per_second']:.1f} files/sec")
        print(f"Cache hit rate: {perf['cache_hit_rate']:.1%}")
        
        dedup = report['deduplication_stats']
        print(f"Unique files: {dedup['unique_files']:,}")
        print(f"Duplicate groups: {dedup['duplicate_groups']:,}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\nExtraction interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
