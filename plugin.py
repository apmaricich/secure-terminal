"""
Secure Terminal Plugin for Hermes Agent

This plugin provides enhanced security for terminal command execution 
by validating commands against configurable security policies before execution.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from hermes_cli.plugin import PluginContext

logger = logging.getLogger(__name__)

class SecureTerminalTool:
    """Secure implementation of terminal execution with validation"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize secure terminal tool with configuration.
        
        Args:
            config: Security configuration dictionary
        """
        self.config = config or {}
        
        # Default security policies - dangerous patterns to block
        self.blocked_patterns = [
            # Privilege escalation
            r'\bsudo\b',
            r'\bchown\b',
            r'\bchmod\b', 
            r'\bpasswd\b',
            r'\buseradd\b',
            r'\bgroupadd\b',
            r'\bsu\b',
            
            # Dangerous file operations  
            r'\brm\s+-rf\b',
            r'\bcp\s+\/etc\b',
            r'\bmv\s+\/etc\b',
            r'\bdd\b',
            r'\bshred\b',
            
            # Process manipulation
            r'\bkill\b',
            r'\bstart\b',
            r'\bstop\b',
            r'\brestart\b',
            r'\bshutdown\b',
            
            # Shell injection patterns
            r';.*&|&.*;',
            r'`[^`]*`',
            r'\$\([^)]*\)',
            
            # System configuration changes
            r'\bsystemctl\b',
            r'\bdnf\b',
            r'\byum\b',
            r'\bapt\b',
            r'\bpip\b',
            r'\bnpm\b',
        ]
        
        # Default whitelisted safe patterns (if whitelist is enabled)
        self.whitelisted_patterns = [
            r'^ls\b.*$',
            r'^echo\b.*$', 
            r'^cat\b.*$',
            r'^grep\b.*$',
            r'^find\b.*$',
            r'^ps\b.*$',
            r'^df\b.*$',
            r'^du\b.*$',
            r'^who\b.*$',
            r'^uname\b.*$',
            r'^pwd\b.*$',
            r'^date\b.*$',
            r'^cal\b.*$',
        ]
        
        # Override defaults with config
        if 'blocked_patterns' in self.config:
            self.blocked_patterns = self.config['blocked_patterns']
            
        if 'whitelisted_patterns' in self.config:
            self.whitelisted_patterns = self.config['whitelisted_patterns']
        
        # Initialize logging for security auditing
        logger.info("Secure terminal tool initialized with %d blocked patterns and %d whitelisted patterns",
                   len(self.blocked_patterns), len(self.whitelisted_patterns))
    
    def execute(self, command: str, **kwargs) -> Dict[str, Any]:
        """
        Execute a shell command with security validation.
        
        Args:
            command: Shell command to execute
            **kwargs: Additional arguments passed to underlying execution
            
        Returns:
            Dictionary containing execution results and status
        """
        # Pre-validation of command
        validation_result = self._validate_command(command)
        
        if not validation_result['allowed']:
            logger.warning("Command blocked by security policy: %s", 
                          validation_result['reason'])
            return {
                "exit_code": -1,
                "error": f"Blocked by security policy: {validation_result['reason']}",
                "success": False,
                "original_command": command,
                "security_violation": True
            }
        
        # Import here to avoid circular imports during plugin loading
        try:
            from tools.terminal_tool import execute_command
            result = execute_command(command, **kwargs)
            
            # Log successful execution for audit purposes  
            logger.info("Secure execution completed: %s", command[:100])
            return result
            
        except Exception as e:
            logger.error("Error executing secure command: %s", str(e))
            return {
                "exit_code": -2, 
                "error": str(e),
                "success": False,
                "original_command": command
            }
    
    def _validate_command(self, command: str) -> Dict[str, Any]:
        """
        Validate command against security policies.
        
        Args:
            command: Command to validate
            
        Returns:
            Validation result dictionary with 'allowed' flag and reason
        """
        # Handle empty or whitespace-only commands as safe (they don't do anything)
        if not command or not command.strip():
            return {"allowed": True, "reason": "Empty/whitespace command allowed"}
        
        # Check for blocked patterns first
        for pattern in self.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return {
                    "allowed": False,
                    "reason": f"Command contains blocked pattern: {pattern}"
                }
        
        # If whitelists exist, ensure command matches one
        if self.whitelisted_patterns and not any(re.match(pattern, command, re.IGNORECASE) 
                         for pattern in self.whitelisted_patterns):
            return {
                "allowed": False,
                "reason": "Command does not match any allowed pattern"
            }
        
        # Command passed all validations
        return {"allowed": True, "reason": "Command passed validation"}
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Get current security configuration and policy information.
        
        Returns:
            Dictionary with security policy details
        """
        return {
            "blocked_patterns": self.blocked_patterns,
            "whitelisted_patterns": self.whitelisted_patterns,
            "total_blocked": len(self.blocked_patterns),
            "total_whitelisted": len(self.whitelisted_patterns),
            "config": self.config
        }

def register(ctx: PluginContext):
    """
    Register the secure terminal plugin with Hermes.
    
    Args:
        ctx: Plugin context for registration
    """
    config = ctx.config.get("secure_terminal", {})
    logger.info("Registering secure terminal plugin with config: %s", str(config))
    
    # Create the secure tool instance
    secure_tool = SecureTerminalTool(config)
    
    # Register the secure terminal tool  
    ctx.register_tool(
        name="secure_terminal",
        description="Secure terminal execution with validation",
        implementation=secure_tool,
        schema={
            "type": "object",
            "properties": {
                "blocked_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Patterns that will block commands"
                },
                "whitelisted_patterns": {
                    "type": "array", 
                    "items": {"type": "string"},
                    "description": "Only commands matching these patterns are allowed"
                }
            }
        }
    )
    
    # Register diagnostic tool
    ctx.register_tool(
        name="security_audit",
        description="Audit current security policies",
        implementation=lambda: secure_tool.get_security_report()
    )
    
    logger.info("Secure terminal plugin registered successfully")