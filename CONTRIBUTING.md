# Contributing to PenHunter

Thank you for your interest in contributing to PenHunter! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/penhunter.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes: `go test ./...`
6. Build and test: `go build -o bin/penhunter main.go`
7. Commit your changes: `git commit -m "Add feature: description"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Open a Pull Request

## Code Style

- Follow Go standard formatting: `go fmt ./...`
- Run `golint` and fix any issues
- Write clear, descriptive commit messages
- Add comments for exported functions and types
- Keep functions focused and small

## Testing

- Write tests for new features
- Ensure all existing tests pass: `go test ./...`
- Test the binary manually before submitting

## Pull Request Process

1. Update the README.md if needed
2. Update version numbers if applicable
3. Add tests for new functionality
4. Ensure the build passes
5. Update CHANGELOG.md with your changes

## Reporting Issues

When reporting issues, please include:
- Description of the problem
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Go version, etc.)
- Any relevant logs or error messages

## Feature Requests

Feature requests are welcome! Please:
- Check if the feature already exists
- Explain the use case
- Describe the expected behavior
- Consider implementation complexity

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Help others learn and grow

## Questions?

Feel free to open an issue for questions or discussions!

Thank you for contributing to PenHunter! 🎉

