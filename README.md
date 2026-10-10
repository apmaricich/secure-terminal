# Secure Terminal Plugin for Hermes Agent

This plugin provides enhanced security for terminal command execution in the Hermes agent system. It implements custom validation logic that blocks dangerous commands while allowing safe operations.

## Features

- **Pattern-based Security**: Blocks common dangerous command patterns using regex matching
- **Whitelist Support**: Allows only specified safe commands to execute
- **Configurable Policies**: Flexible security policies through configuration files
- **Audit Logging**: Comprehensive logging of all command executions for security monitoring
- **Zero Trust Implementation**: Validates all commands before execution

## Security Controls

The plugin blocks the following dangerous patterns:
- Privilege escalation (sudo, su, chown, chmod)
- File system destruction (rm -rf, dd, shred)
- Process manipulation (kill, start, stop)
- Shell injection patterns
- System configuration changes

## Installation

1. Place this directory in `~/.hermes/plugins/`
2. Run `hermes plugins enable secure-terminal`
3. Configure policies in `~/.hermes/config.yaml`

## Configuration

```yaml
tools:
  secure_terminal:
    blocked_patterns:
      - "\\bsudo\\b"
      - "\\brm\\s+-rf\\b"
    whitelisted_patterns:
      - "^ls\\s+.*$"
      - "^echo\\s+.*$"
```

## Usage

This plugin replaces the default terminal tool with enhanced security. All commands are validated before execution.