# Resilience Forge Contribution Guidelines

## Welcome!

Resilience Forge is an open-source project dedicated to building ransomware-proof architecture. We welcome contributions from security engineers, ML researchers, DevOps specialists, and community members.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Report security vulnerabilities responsibly (security@example.com)

## How to Contribute

### 1. **Defensive Layer Improvements**
- Enhance ML detection patterns
- Improve isolation strategies
- Optimize recovery processes
- Add new behavioral fingerprints

### 2. **Testing & Validation**
- Add test scenarios to The Gauntlet
- Improve coverage of edge cases
- Validate against known malware families
- Performance benchmarking

### 3. **Documentation**
- Architecture diagrams
- Operational guides
- Forensic procedures
- Threat intelligence integration

### 4. **Infrastructure & DevOps**
- Container optimizations
- Kubernetes manifests
- CI/CD pipeline enhancements
- Cloud provider integrations (AWS, Azure, GCP)

## Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/resilience-forge.git
cd resilience-forge

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Start infrastructure
docker-compose up -d

# Run tests
pytest tests/

# Start development server
cd backend
uvicorn main:app --reload
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-improvement`
3. Make focused, well-documented changes
4. Add tests for new functionality
5. Run the test suite: `pytest tests/`
6. Commit with clear messages: `git commit -m "Add: feature description"`
7. Push to fork: `git push origin feature/your-improvement`
8. Submit Pull Request with clear description

## Testing Requirements

All PRs must pass:
- Unit tests: `pytest tests/`
- Integration tests: `pytest tests/test_gauntlet.py`
- Data loss requirement: < 0.1% in recovery scenarios
- MTTC requirement: Mean Time to Contain < 60 seconds
- Immutability validation: All logs must remain tamper-proof

## Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types: `add`, `fix`, `improve`, `docs`, `test`, `refactor`

Examples:
- `add: ML entropy detection for encrypted file patterns`
- `fix: isolation timeout in micro-segmentation`
- `improve: MTTC performance by 23%`

## Defensibility Index Contributions

When adding new defensive capabilities, clearly document:
- Component being improved (Detection, Isolation, Recovery, Immutability)
- How it enhances the Defensibility Index
- Benchmark improvements
- Community percentile impact

## Reporting Issues

- **Security vulnerabilities**: security@example.com (NOT github issues)
- **Bugs**: GitHub Issues with reproduction steps
- **Feature requests**: GitHub Discussions with use cases
- **Documentation**: Direct PRs with corrections

## Questions?

- Join our Discord: https://discord.gg/resilience-forge
- GitHub Discussions: https://github.com/yourorg/resilience-forge/discussions
- Community Docs: https://docs.resilience-forge.com

Thank you for building more resilient infrastructure! 🔥🛡️
