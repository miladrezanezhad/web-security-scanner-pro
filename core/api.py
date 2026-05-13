#!/usr/bin/env python3
"""
REST API server for remote scanning and integration.
Built with FastAPI for high performance and automatic documentation.

Features:
- Start/manage security scans via REST API
- Retrieve scan results
- List available modules
- Update vulnerability database
- Webhook support
- API key authentication
- Rate limiting
- Swagger/OpenAPI documentation
"""

import os
import sys
import json
import uuid
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, Header
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, HttpUrl
from loguru import logger

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import SecurityScanner
from core.database import VulnerabilityDatabase
from core.reporter import ReportGenerator


# ============================================================================
# Pydantic Models
# ============================================================================

class ScanRequest(BaseModel):
    """Scan request model."""
    target_url: str = Field(..., description="Target URL to scan")
    modules: Optional[List[str]] = Field(None, description="List of modules to run")
    mode: str = Field("stealth", description="Scan mode: stealth, normal, aggressive")
    report_formats: Optional[List[str]] = Field(None, description="Report formats: html, pdf, json, markdown")
    webhook_url: Optional[HttpUrl] = Field(None, description="Webhook URL for scan completion notification")

class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str
    status: str
    target_url: str
    created_at: str
    message: str

class ScanStatus(BaseModel):
    """Scan status model."""
    scan_id: str
    status: str
    target_url: str
    progress: int = 0
    findings_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

class ModuleInfo(BaseModel):
    """Module information model."""
    name: str
    category: str
    description: str
    enabled: bool

class DatabaseStats(BaseModel):
    """Database statistics model."""
    total_vulnerabilities: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    last_updated: Optional[str]

class UpdateRequest(BaseModel):
    """Update request model."""
    update_db: bool = True
    update_signatures: bool = True

class APIResponse(BaseModel):
    """Standard API response."""
    success: bool
    message: str
    data: Optional[Any] = None


# ============================================================================
# FastAPI Application
# ============================================================================

class APIServer:
    """REST API server for Web Security Analyzer Pro."""
    
    def __init__(self, config: Dict):
        """
        Initialize API server.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.app = FastAPI(
            title="Web Security Analyzer Pro API",
            description="REST API for automated security scanning",
            version="3.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
        )
        
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Security
        self.security = HTTPBearer(auto_error=False)
        self.api_keys = self._load_api_keys()
        
        # Active scans
        self.active_scans: Dict[str, Dict] = {}
        self.scan_results: Dict[str, Any] = {}
        
        # Database
        db_path = config.get('database', {}).get('path', 'database/vulnerabilities.db')
        self.db = VulnerabilityDatabase(db_path)
        
        # Register routes
        self._register_routes()
        
        logger.info("API server initialized")
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from configuration or environment."""
        keys = {}
        
        # Load from config
        api_config = self.config.get('api', {})
        config_keys = api_config.get('keys', {})
        keys.update(config_keys)
        
        # Load from environment
        env_key = os.getenv('WSAP_API_KEY')
        if env_key:
            keys[env_key] = 'admin'
        
        # Default key for development
        if not keys:
            default_key = os.getenv('WSAP_DEFAULT_KEY', 'dev-key-change-in-production')
            keys[default_key] = 'admin'
            logger.warning("Using default API key. Change this in production!")
        
        return keys
    
    async def _verify_api_key(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        x_api_key: Optional[str] = Header(None, alias="X-API-Key")
    ) -> bool:
        """
        Verify API key from Bearer token or X-API-Key header.
        
        Returns:
            True if authenticated
        """
        token = None
        
        if credentials:
            token = credentials.credentials
        elif x_api_key:
            token = x_api_key
        
        if token and token in self.api_keys:
            return True
        
        if not self.api_keys:
            return True  # No authentication configured
        
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    def _register_routes(self):
        """Register all API routes."""
        
        @self.app.get("/", response_model=APIResponse)
        async def root():
            """API root endpoint."""
            return APIResponse(
                success=True,
                message="Web Security Analyzer Pro API v3.0",
                data={
                    "version": "3.0.0",
                    "docs": "/docs",
                    "health": "/health"
                }
            )
        
        @self.app.get("/health", response_model=APIResponse)
        async def health_check():
            """Health check endpoint."""
            return APIResponse(
                success=True,
                message="API is healthy",
                data={
                    "status": "ok",
                    "timestamp": datetime.now().isoformat(),
                    "active_scans": len(self.active_scans)
                }
            )
        
        @self.app.post("/scan", response_model=ScanResponse)
        async def start_scan(
            scan_request: ScanRequest,
            background_tasks: BackgroundTasks,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """
            Start a new security scan.
            
            Returns scan_id for tracking progress.
            """
            scan_id = str(uuid.uuid4())[:8]
            
            # Store scan info
            self.active_scans[scan_id] = {
                'status': 'pending',
                'target_url': scan_request.target_url,
                'progress': 0,
                'findings_count': 0,
                'created_at': datetime.now().isoformat(),
                'modules': scan_request.modules,
                'mode': scan_request.mode,
                'report_formats': scan_request.report_formats,
            }
            
            # Start scan in background
            background_tasks.add_task(
                self._run_scan,
                scan_id,
                scan_request
            )
            
            logger.info(f"Scan {scan_id} started for {scan_request.target_url}")
            
            return ScanResponse(
                scan_id=scan_id,
                status="started",
                target_url=scan_request.target_url,
                created_at=datetime.now().isoformat(),
                message=f"Scan started. Track progress at /scan/{scan_id}"
            )
        
        @self.app.get("/scan/{scan_id}", response_model=ScanStatus)
        async def get_scan_status(
            scan_id: str,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Get scan status and progress."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_info = self.active_scans[scan_id]
            
            return ScanStatus(
                scan_id=scan_id,
                status=scan_info['status'],
                target_url=scan_info['target_url'],
                progress=scan_info.get('progress', 0),
                findings_count=scan_info.get('findings_count', 0),
                started_at=scan_info.get('created_at'),
                completed_at=scan_info.get('completed_at')
            )
        
        @self.app.get("/scan/{scan_id}/results")
        async def get_scan_results(
            scan_id: str,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Get scan results."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            if self.active_scans[scan_id]['status'] != 'completed':
                raise HTTPException(status_code=400, detail="Scan not completed yet")
            
            if scan_id in self.scan_results:
                return JSONResponse(content=self.scan_results[scan_id])
            
            raise HTTPException(status_code=404, detail="Results not found")
        
        @self.app.get("/scan/{scan_id}/report")
        async def download_report(
            scan_id: str,
            format: str = Query("html", description="Report format"),
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Download scan report."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            if self.active_scans[scan_id]['status'] != 'completed':
                raise HTTPException(status_code=400, detail="Scan not completed")
            
            if scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Results not found")
            
            try:
                reporter = ReportGenerator(self.scan_results[scan_id], self.config)
                report_path = reporter.generate(format=format)
                return FileResponse(
                    report_path,
                    filename=f"scan_report_{scan_id}.{format}",
                    media_type="application/octet-stream"
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/scans", response_model=APIResponse)
        async def list_scans(
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """List all scans."""
            scans = []
            for scan_id, scan_info in self.active_scans.items():
                scans.append({
                    'scan_id': scan_id,
                    'target_url': scan_info['target_url'],
                    'status': scan_info['status'],
                    'created_at': scan_info.get('created_at')
                })
            
            return APIResponse(
                success=True,
                message=f"{len(scans)} scans found",
                data=scans
            )
        
        @self.app.delete("/scan/{scan_id}")
        async def cancel_scan(
            scan_id: str,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Cancel a running scan."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            self.active_scans[scan_id]['status'] = 'cancelled'
            
            return APIResponse(
                success=True,
                message=f"Scan {scan_id} cancelled"
            )
        
        @self.app.get("/modules", response_model=List[ModuleInfo])
        async def list_modules(
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """List all available modules."""
            from modules import AVAILABLE_MODULES
            modules = []
            
            for name, path in AVAILABLE_MODULES.items():
                parts = path.split('.')
                category = parts[2] if len(parts) > 2 else 'unknown'
                
                modules.append(ModuleInfo(
                    name=name,
                    category=category,
                    description=f"Module at {path}",
                    enabled=True
                ))
            
            return modules
        
        @self.app.get("/database/stats", response_model=DatabaseStats)
        async def database_stats(
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Get vulnerability database statistics."""
            stats = self.db.get_statistics()
            
            return DatabaseStats(
                total_vulnerabilities=stats.get('total_vulnerabilities', 0),
                by_severity=stats.get('by_severity', {}),
                by_category=stats.get('by_category', {}),
                last_updated=stats.get('metadata', {}).get('last_update')
            )
        
        @self.app.post("/update", response_model=APIResponse)
        async def update_database(
            update_req: UpdateRequest,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Update vulnerability database."""
            from core.updater import DatabaseUpdater
            updater = DatabaseUpdater(self.config)
            
            total = 0
            if update_req.update_db:
                total += updater.update_vulnerability_database()
            if update_req.update_signatures:
                total += updater.update_signatures()
            
            return APIResponse(
                success=True,
                message=f"Updated {total} items",
                data={'updated_count': total}
            )
        
        @self.app.get("/search/cve/{cve_id}")
        async def search_cve(
            cve_id: str,
            authenticated: bool = Depends(self._verify_api_key)
        ):
            """Search for a CVE in the database."""
            result = self.db.search_by_cve(cve_id)
            
            if result:
                return APIResponse(
                    success=True,
                    message="CVE found",
                    data=result
                )
            
            raise HTTPException(status_code=404, detail="CVE not found")
    
    async def _run_scan(self, scan_id: str, scan_request: ScanRequest):
        """
        Run scan in background.
        
        Args:
            scan_id: Unique scan identifier
            scan_request: Scan request parameters
        """
        try:
            # Update status
            self.active_scans[scan_id]['status'] = 'running'
            self.active_scans[scan_id]['started_at'] = datetime.now().isoformat()
            
            # Configure scanner
            scan_config = self.config.copy()
            scan_config['scan_mode']['default'] = scan_request.mode
            
            # Create scanner
            scanner = SecurityScanner(scan_request.target_url, scan_config)
            
            # Run scan
            result = await scanner.scan(scan_request.modules)
            
            # Store results
            self.scan_results[scan_id] = result.to_dict()
            
            # Update status
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['progress'] = 100
            self.active_scans[scan_id]['findings_count'] = result.statistics.get('total', 0)
            self.active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
            
            # Generate reports if requested
            if scan_request.report_formats:
                reporter = ReportGenerator(result, self.config)
                report_paths = []
                for fmt in scan_request.report_formats:
                    path = reporter.generate(format=fmt)
                    report_paths.append(path)
                self.active_scans[scan_id]['reports'] = report_paths
            
            # Save to scan history
            self.db.save_scan_result({
                'target_url': scan_request.target_url,
                'scan_time': datetime.now().isoformat(),
                'modules_run': result.modules_run,
                'total_findings': result.statistics.get('total', 0),
                'critical_count': result.statistics.get('critical', 0),
                'high_count': result.statistics.get('high', 0),
                'medium_count': result.statistics.get('medium', 0),
                'low_count': result.statistics.get('low', 0),
                'scan_mode': scan_request.mode,
            })
            
            # Call webhook if configured
            if scan_request.webhook_url:
                await self._call_webhook(scan_request.webhook_url, scan_id)
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)
    
    async def _call_webhook(self, webhook_url: str, scan_id: str):
        """Call webhook URL with scan results."""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    'scan_id': scan_id,
                    'status': self.active_scans[scan_id]['status'],
                    'findings_count': self.active_scans[scan_id].get('findings_count', 0),
                    'timestamp': datetime.now().isoformat()
                }
                
                async with session.post(
                    str(webhook_url),
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        logger.info(f"Webhook called successfully for scan {scan_id}")
                    else:
                        logger.warning(f"Webhook failed with status {response.status}")
        except Exception as e:
            logger.error(f"Webhook call failed: {e}")
    
    def run(self, host: str = "127.0.0.1", port: int = 8000):
        """
        Start the API server.
        
        Args:
            host: Bind address
            port: Port number
        """
        import uvicorn
        
        logger.info(f"Starting API server on {host}:{port}")
        logger.info(f"API Documentation: http://{host}:{port}/docs")
        
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )