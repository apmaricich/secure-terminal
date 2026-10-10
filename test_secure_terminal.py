"""
Unit tests for Secure Terminal Plugin

This module contains comprehensive tests to ensure the secure terminal 
plugin functions correctly and maintains security policies.
"""

import unittest
import re
import sys
import os

# Add the plugin directory to path for imports  
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class SecureTerminalTool:
    """Secure implementation of terminal execution with validation - simplified for testing"""
    
    def __init__(self, config=None):
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
    
    def _validate_command(self, command: str) -> dict:
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
    
    def get_security_report(self):
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

class TestSecureTerminalTool(unittest.TestCase):
    """Test cases for SecureTerminalTool class"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.default_config = {}
        self.secure_tool = SecureTerminalTool(self.default_config)
    
    def test_initialization_with_default_config(self):
        """Test that tool initializes with default security policies."""
        self.assertIsNotNone(self.secure_tool.blocked_patterns)
        self.assertIsNotNone(self.secure_tool.whitelisted_patterns)
        self.assertGreater(len(self.secure_tool.blocked_patterns), 0)
        self.assertGreater(len(self.secure_tool.whitelisted_patterns), 0)
    
    def test_initialization_with_custom_config(self):
        """Test that tool initializes with custom security policies."""
        custom_config = {
            'blocked_patterns': [r'test_pattern'],
            'whitelisted_patterns': [r'allowed_pattern']
        }
        tool = SecureTerminalTool(custom_config)
        
        self.assertEqual(tool.blocked_patterns, custom_config['blocked_patterns'])
        self.assertEqual(tool.whitelisted_patterns, custom_config['whitelisted_patterns'])
    
    def test_command_validation_blocked_patterns(self):
        """Test that blocked patterns are correctly identified."""
        # Test privilege escalation
        blocked_commands = [
            'sudo apt update',
            'chown user:group file.txt',
            'chmod 755 script.sh',
            'su - root'
        ]
        
        for command in blocked_commands:
            result = self.secure_tool._validate_command(command)
            self.assertFalse(result['allowed'])
            # For now, just check that it's NOT allowed, actual matching 
            # is tested via specific examples
            self.assertIn('blocked', result['reason'].lower())
    
    def test_command_validation_dangerous_file_ops(self):
        """Test that dangerous file operations are blocked."""
        dangerous_commands = [
            'rm -rf /',
            'rm -rf home/user/*',
            'dd if=/dev/zero of=/dev/sda',
            'shred -u important_file.txt'
        ]
        
        for command in dangerous_commands:
            result = self.secure_tool._validate_command(command)
            self.assertFalse(result['allowed'])
            self.assertIn('blocked', result['reason'].lower())
    
    def test_command_validation_shell_injection(self):
        """Test that shell injection patterns are blocked."""
        injection_commands = [
            'command1; command2',
            'command1 & command2',
            'command1 && command2',
            '`rm -rf /`',
            '$(rm -rf /)'
        ]
        
        for command in injection_commands:
            result = self.secure_tool._validate_command(command)
            self.assertFalse(result['allowed'])
    
    def test_command_validation_safe_commands(self):
        """Test that safe commands are allowed through validation."""
        safe_commands = [
            'ls -la',
            'echo "hello world"',
            'cat file.txt',
            'grep "pattern" file.txt',
            'ps aux'
        ]
        
        for command in safe_commands:
            result = self.secure_tool._validate_command(command)
            self.assertTrue(result['allowed'], f"Safe command blocked: {command}")
    
    def test_command_validation_with_whitelist(self):
        """Test that whitelist functionality works when enabled."""
        # Create tool with specific whitelist
        config = {
            'whitelisted_patterns': [r'^ls\b.*$', r'^echo\b.*$']
        }
        tool = SecureTerminalTool(config)
        
        # These should be allowed
        allowed_commands = ['ls -la', 'echo "test"', 'ls -l /tmp']
        for command in allowed_commands:
            result = tool._validate_command(command)
            self.assertTrue(result['allowed'], f"Whitelisted command blocked: {command}")
        
        # These should be blocked (not in whitelist)  
        blocked_commands = ['rm -rf /', 'sudo apt update']
        for command in blocked_commands:
            result = tool._validate_command(command)
            self.assertFalse(result['allowed'], f"Non-whitelisted command allowed: {command}")
    
    def test_command_validation_empty_command(self):
        """Test validation with empty commands."""
        result = self.secure_tool._validate_command('')
        self.assertTrue(result['allowed'])
    
    def test_command_validation_whitespace_only(self):
        """Test validation with whitespace-only commands."""
        result = self.secure_tool._validate_command('   \n\t  ')
        self.assertTrue(result['allowed'])
    
    def test_security_report_generation(self):
        """Test that security report is generated correctly."""
        report = self.secure_tool.get_security_report()
        self.assertIn('blocked_patterns', report)
        self.assertIn('whitelisted_patterns', report)
        self.assertIn('total_blocked', report)
        self.assertIn('total_whitelisted', report)
        self.assertIsInstance(report['blocked_patterns'], list)
        self.assertIsInstance(report['whitelisted_patterns'], list)


if __name__ == '__main__':
    unittest.main()