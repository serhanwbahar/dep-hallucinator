# Branching Strategy

## Branch Structure

### `master` - Production Branch
- **Protected branch** - requires review
- Contains production-ready code
- Tagged releases created from this branch
- Direct pushes **prohibited**

### `develop` - Default Development Branch  
- **Default branch** for new contributions
- Integration branch for features
- Continuous development happens here
- Automatically tested on each push

### Feature Branches
- Created from `develop`
- Named: `feature/description` or `fix/description`
- Merged back to `develop` via PR

## Workflow

### For Contributors

1. **Fork the repository** on GitHub
2. **Clone your fork**
   ```bash
   git clone <your-fork-url>
   cd dep-hallucinator
   ```

3. **Create feature branch from develop**
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

4. **Make changes and commit**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request to `develop`**
   - Use the PR template
   - Ensure tests pass
   - Request review

### For Maintainers

#### Merging to develop
- Review code changes
- Ensure tests pass
- Merge feature PRs to `develop`

#### Releasing to master
1. **Create release PR from develop to master**
   ```bash
   git checkout master
   git pull origin master
   git checkout -b release/v1.x.x
   git merge develop
   git push origin release/v1.x.x
   ```

2. **Create PR: release/v1.x.x → master**
3. **Review and merge** (requires maintainer approval)
4. **Tag release**
   ```bash
   git checkout master
   git pull origin master
   git tag -a v1.x.x -m "Release v1.x.x"
   git push origin v1.x.x
   ```

## Branch Protection Rules

### `master` Branch
- Require pull request reviews (1+ maintainer)
- Require status checks (tests, linting, security)
- Require branches to be up to date
- Restrict pushes to maintainers only
- No force pushes allowed

### `develop` Branch  
- Require status checks (tests pass)
- Allow maintainer bypass for hotfixes

## Security Requirements

All PRs to `master` must pass:
- ✅ Test suite
- ✅ Linting checks  
- ✅ Security scans
- ✅ Maintainer code review
- ✅ Up-to-date with target branch 