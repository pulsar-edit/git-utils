const path = require('path')
const fs = require('fs-plus')
const {Repository} = require('../build/Release/git.node')

const statusIndexNew = 1 << 0
const statusIndexModified = 1 << 1
const statusIndexDeleted = 1 << 2
const statusIndexRenamed = 1 << 3
const statusIndexTypeChange = 1 << 4
const statusWorkingDirNew = 1 << 7
const statusWorkingDirModified = 1 << 8
const statusWorkingDirDelete = 1 << 9
const statusWorkingDirTypeChange = 1 << 10
const statusIgnored = 1 << 14

const modifiedStatusFlags =
  statusWorkingDirModified |
  statusIndexModified |
  statusWorkingDirDelete |
  statusIndexDeleted |
  statusWorkingDirTypeChange |
  statusIndexTypeChange

const newStatusFlags = statusWorkingDirNew | statusIndexNew

const deletedStatusFlags = statusWorkingDirDelete | statusIndexDeleted

const indexStatusFlags =
  statusIndexNew |
  statusIndexModified |
  statusIndexDeleted |
  statusIndexRenamed |
  statusIndexTypeChange


const IS_WINDOWS = process.platform === 'win32'

// Given a path on disk (real or hypothetical), attempt to normalize it by
// (optionally) resolving `realpath` and (if on Windows) converting all path
// separators to forward slashes.
//
// Note that `useRealpath: false` is only honored off Windows. On Windows we
// resolve `realpath` unconditionally, and that is deliberate rather than an
// oversight: a path we haven't resolved may still be in 8.3 short form, and a
// short path compares unequal to its own long form no matter how carefully we
// normalize case and separators. Callers pass `useRealpath: false` to skip
// work they believe is redundant, but on Windows it isn't redundant — skipping
// it would make paths like `C:/Users/RUNNER~1/repo` fail to match the very
// directory they name. See `realpath` for why `realpathSync.native` is the
// thing that expands them.
function normalizePath (filePath, useRealpath = true) {
  if (typeof filePath !== 'string') return filePath

  if (useRealpath) {
    filePath = realpath(filePath)
  }
  if (!IS_WINDOWS) return filePath
  return realpath(filePath).replace(/\\/g, '/')
}

// Compare two paths to determine whether they resolve to the same file or
// directory on disk.
//
// This is more complicated than it sounds — not just because of symlinks but
// also because of files/directories on Windows possibly having both a short
// name and a long name.
function pathsAreEqual (pathA, pathB, caseInsensitive = false, useRealpath = true) {
  if (typeof pathA !== 'string' || typeof pathB !== 'string') {
    return false
  }

  pathA = normalizePath(pathA, useRealpath)
  pathB = normalizePath(pathB, useRealpath)

  if (IS_WINDOWS || caseInsensitive) {
    pathA = pathA.toLowerCase()
    pathB = pathB.toLowerCase()
  }

  let result = pathA === pathB
  if (result || !IS_WINDOWS) return result
  // If neither path includes an 8.3 short name, we can skip some paranoid
  // path equality checks.
  if (!pathA.includes('~') && !pathB.includes('~')) {
    return result
  }

  // If we get this far, we're on Windows and comparing two paths, at least one
  // of which contains an 8.3 short name. The only obvious and reliable way to
  // address this is to `statSync` both paths and verify their IDs are the
  // same.
  //
  // The `bigint` option matters here: without it, Windows file indices are
  // returned as ordinary numbers and can silently lose precision, which would
  // make two distinct files compare as equal.
  try {
    const statA = fs.statSync(pathA, { bigint: true })
    const statB = fs.statSync(pathB, { bigint: true })
    return statA.ino === statB.ino && statA.dev === statB.dev
  } catch (e) {
    // Either path may not exist (or may not be readable); fall back to the
    // plain string comparison.
    return result
  }
}

// Returns whether `pathA` starts with `pathB` — i.e., whether `pathB` is equal
// to `pathA` or else one of its ancestor directories.
function pathStartsWith (pathA, pathB, caseInsensitive = false, useRealpath = true) {
  if (IS_WINDOWS) {
    pathA = normalizePath(pathA, useRealpath)
    pathB = normalizePath(pathB, useRealpath)
  }
  if (caseInsensitive) {
    pathA = pathA.toLowerCase()
    pathB = pathB.toLowerCase()
  }
  if (!pathB.endsWith(`/`)) {
    pathB = `${pathB}/`
  }
  return pathA.startsWith(pathB)
}

// Convert Windows path separators to forward slashes. Purely a string
// operation — unlike `normalizePath`, this never touches the filesystem.
function toSlashes (filePath) {
  return IS_WINDOWS ? filePath.replace(/\\/g, '/') : filePath
}

// If `filePath` lies within `workingDirectory`, return its path relative to
// that directory; otherwise return `null`.
//
// This compares the two as plain strings and does no filesystem access of its
// own; both arguments must already be in the same form. Note that the slice
// below is taken against `workingDirectory` *after* any trailing slash is
// removed, since matching on one value and slicing by the length of another is
// how you produce a silently corrupt relative path.
function relativizeAgainst (filePath, workingDirectory, caseInsensitive) {
  let comparablePath = filePath
  let comparableWorkingDirectory = trimPath(workingDirectory)

  if (IS_WINDOWS || caseInsensitive) {
    comparablePath = comparablePath.toLowerCase()
    comparableWorkingDirectory = comparableWorkingDirectory.toLowerCase()
  }

  if (comparablePath === comparableWorkingDirectory) return ''
  if (comparablePath.startsWith(`${comparableWorkingDirectory}/`)) {
    return filePath.substring(comparableWorkingDirectory.length + 1)
  }
  return null
}

// The working directories a path may be relativized against, in canonical
// (symlink- and short-name-resolved) form.
//
// Resolving these means touching the filesystem, but they can't change while
// the repository is open — so we do it once, on the first call that actually
// needs it, and remember the answer rather than paying for it on every
// `relativize`.
function canonicalWorkingDirectories (repository) {
  if (!repository.canonicalWorkingDirectories) {
    repository.canonicalWorkingDirectories = [
      repository.getWorkingDirectory(),
      repository.openedWorkingDirectory
    ].filter(Boolean).map(workingDirectory => normalizePath(workingDirectory))
  }
  return repository.canonicalWorkingDirectories
}

Repository.prototype.release = function () {
  for (let submodulePath in this.submodules) {
    const submoduleRepo = this.submodules[submodulePath]
    if (submoduleRepo) submoduleRepo.release()
  }
  return this._release()
}

Repository.prototype.getWorkingDirectory = function () {
  if (!this.workingDirectory) {
    this.workingDirectory = this._getWorkingDirectory()
    if (this.workingDirectory) this.workingDirectory = this.workingDirectory.replace(/\/$/, '')
  }
  return this.workingDirectory
}

Repository.prototype.getShortHead = function () {
  const head = this.getHead()
  if (head == null) return head
  if (head.startsWith('refs/heads/')) return head.substring(11)
  if (head.startsWith('refs/tags/')) return head.substring(10)
  if (head.startsWith('refs/remotes/')) return head.substring(13)
  if (head.match(/[a-fA-F0-9]{40}/)) return head.substring(0, 7)
  return head
}

Repository.prototype.isStatusModified = function (status = 0) {
  return (status & modifiedStatusFlags) > 0
}

Repository.prototype.isPathModified = function (path) {
  return this.isStatusModified(this.getStatus(path))
}

Repository.prototype.isStatusNew = function (status = 0) {
  return (status & newStatusFlags) > 0
}

Repository.prototype.isPathNew = function (path) {
  return this.isStatusNew(this.getStatus(path))
}

Repository.prototype.isStatusDeleted = function (status = 0) {
  return (status & deletedStatusFlags) > 0
}

Repository.prototype.isPathDeleted = function (path) {
  return this.isStatusDeleted(this.getStatus(path))
}

Repository.prototype.isPathStaged = function (path) {
  return this.isStatusStaged(this.getStatus(path))
}

Repository.prototype.isStatusIgnored = function (status = 0) {
  return (status & statusIgnored) > 0
}

Repository.prototype.isStatusStaged = function (status = 0) {
  return (status & indexStatusFlags) > 0
}

Repository.prototype.getUpstreamBranch = function (branch) {
  if (branch == null) branch = this.getHead()
  if (!branch || !branch.startsWith('refs/heads/')) return null
  const shortBranch = branch.substring(11)

  const branchMerge = this.getConfigValue(`branch.${shortBranch}.merge`)
  if (!branchMerge || !branchMerge.startsWith('refs/heads/')) return null
  const shortBranchMerge = branchMerge.substring(11)

  const branchRemote = this.getConfigValue(`branch.${shortBranch}.remote`)
  if (!branch || branch.length === 0) return null

  return `refs/remotes/${branchRemote}/${shortBranchMerge}`
}

Repository.prototype.getRemoteHead = function (remoteName = 'origin') {
  return this.getSymbolicRefTarget(`refs/remotes/${remoteName}/HEAD`)
}

Repository.prototype.getAheadBehindCount = function (branch = 'HEAD') {
  if (branch !== 'HEAD' && !branch.startsWith('refs/heads/')) {
    branch = `refs/heads/${branch}`
  }

  const headCommit = this.getReferenceTarget(branch)
  if (!headCommit || headCommit.length === 0) return {ahead: 0, behind: 0}

  const upstream = this.getUpstreamBranch()
  if (!upstream || upstream.length === 0) return {ahead: 0, behind: 0}

  const upstreamCommit = this.getReferenceTarget(upstream)
  if (!upstreamCommit || upstreamCommit.length === 0) return {ahead: 0, behind: 0}

  return this.compareCommits(headCommit, upstreamCommit)
}

Repository.prototype.getAheadBehindCountAsync = async function (branch = 'HEAD') {
  if (branch !== 'HEAD' && !branch.startsWith('refs/heads/')) {
    branch = `refs/heads/${branch}`
  }

  const headCommit = this.getReferenceTarget(branch)
  if (!headCommit || headCommit.length === 0) return {ahead: 0, behind: 0}

  const upstream = this.getUpstreamBranch()
  if (!upstream || upstream.length === 0) return {ahead: 0, behind: 0}

  const upstreamCommit = this.getReferenceTarget(upstream)
  if (!upstreamCommit || upstreamCommit.length === 0) return {ahead: 0, behind: 0}

  return performAsyncWork(this, done => this.compareCommitsAsync(
    done,
    headCommit,
    upstreamCommit
  ))
}

Repository.prototype.checkoutReference = function (branch, create) {
  if (branch.indexOf('refs/heads/') !== 0) branch = `refs/heads/${branch}`
  return this.checkoutRef(branch, create)
}

Repository.prototype.relativize = function (filePath) {
  if (!filePath) return filePath
  filePath = toSlashes(filePath)

  if (!IS_WINDOWS && filePath[0] !== '/') {
    return filePath
  }

  // Fast path: compare as plain strings, touching the filesystem not at all.
  // This is what succeeds for nearly every call, since the path we're handed
  // and the working directory are usually already in the same form.
  for (let workingDirectory of [this.getWorkingDirectory(), this.openedWorkingDirectory]) {
    if (!workingDirectory) continue
    const relativePath = relativizeAgainst(
      filePath,
      toSlashes(workingDirectory),
      this.caseInsensitiveFs
    )
    if (relativePath !== null) return relativePath
  }

  // Slow path: the strings didn't match, but they may still name the same
  // place — through a symlink, or an 8.3 short name on Windows. Resolve both
  // sides for real and try once more.
  //
  // A miss costs roughly what *every* call used to cost, so this is no worse
  // than the previous behavior in the worst case, while a hit above now costs
  // nothing at all.
  const realFilePath = realpathRecursive(filePath)
  for (let workingDirectory of canonicalWorkingDirectories(this)) {
    const relativePath = relativizeAgainst(realFilePath, workingDirectory, this.caseInsensitiveFs)
    if (relativePath !== null) return relativePath
  }

  return filePath
}

Repository.prototype.submoduleForPath = function (filePath) {
  filePath = this.relativize(filePath)
  if (!filePath) return null

  for (let submodulePath in this.submodules) {
    const submoduleRepo = this.submodules[submodulePath]
    if (filePath === submodulePath) {
      return submoduleRepo
    } else if (filePath.startsWith(`${submodulePath}/`)) {
      filePath = filePath.substring(submodulePath.length + 1)
      return submoduleRepo.submoduleForPath(filePath) || submoduleRepo
    }
  }

  return null
}

Repository.prototype.isWorkingDirectory = function (dirPath) {
  if (!dirPath) return false
  dirPath = normalizePath(dirPath)

  if (!IS_WINDOWS && dirPath[0] !== '/') {
    return false
  }

  let workingDirectory = this.getWorkingDirectory()
  if (workingDirectory && pathsAreEqual(workingDirectory, dirPath, this.caseInsensitiveFs)) {
    return true
  }

  let openedWorkingDirectory = this.openedWorkingDirectory
  if (openedWorkingDirectory && pathsAreEqual(openedWorkingDirectory, dirPath, this.caseInsensitiveFs)) {
    return true
  }

  return false
}

const {getHeadAsync, getStatus, getStatusAsync, getStatusForPath} = Repository.prototype
delete Repository.prototype.getStatusForPath

Repository.prototype.getStatusForPaths = function (paths) {
  if (paths && paths.length > 0) {
    return getStatus.call(this, paths)
  } else {
    return {}
  }
}

Repository.prototype.getStatus = function (filePath) {
  if (typeof filePath === 'string') {
    return getStatusForPath.call(this, filePath)
  } else {
    return getStatus.call(this)
  }
}

Repository.prototype.getHeadAsync = function () {
  return performAsyncWork(this, done => getHeadAsync.call(this, done))
}

Repository.prototype.getStatusAsync = function () {
  return performAsyncWork(this, done => getStatusAsync.call(this, done))
}

Repository.prototype.getStatusForPathsAsync = function (paths) {
  return performAsyncWork(this, done => getStatusAsync.call(this, done, paths))
}

function performAsyncWork (repo, fn) {
  fn = promisify(fn)

  if (repo._lastAsyncPromise) {
    repo._lastAsyncPromise = repo._lastAsyncPromise.then(fn, fn)
  } else {
    repo._lastAsyncPromise = fn()
  }
  return repo._lastAsyncPromise
}

function promisify (fn) {
  return () => new Promise((resolve, reject) =>
    fn((error, result) => error ? reject(error) : resolve(result))
  )
}

// Given `unrealPath` — which may or may not exist on disk in its current form
// — resolve to a real path on disk, if possible.
//
// This is done by traversing upward to the first directory that _does_ exist,
// then getting its `realpath` and appending the rest back on.
function realpathRecursive (unrealPath) {
  let currentPath = unrealPath
  let result = null
  let remainder = ''
  if (!path.isAbsolute(unrealPath)) {
    return realpath(unrealPath)
  }
  let parent = parentPath(currentPath)
  while (parent !== null) {
    try {
      result = fs.realpathSync.native(currentPath)
      break
    } catch (e) {
      if (e.code === 'ENOENT') {
        currentPath = parent
        remainder = path.relative(currentPath, unrealPath)
        parent = parentPath(currentPath)
      } else {
        return unrealPath
      }
    }
  }
  // We climbed all the way to a root without resolving anything.
  if (result === null) {
    return unrealPath
  }
  // `toSlashes` rather than `normalizePath`: resolving this again could never
  // find anything new. Either the loop broke immediately, in which case
  // `result` is already resolved and `remainder` is empty, or it climbed — and
  // it only climbs past a level that reported ENOENT, so the tail we just
  // reattached is known not to exist. All that's left to do is fix up the
  // separators.
  return toSlashes(trimPath(`${result}/${remainder}`))
}

function trimPath (filePath) {
  if (!filePath.endsWith('/')) return filePath
  return filePath.replace(/\/$/, '')
}

// Attempts to resolve a path to its real path on disk; if it fails, returns
// the original path.
function realpath (unrealPath) {
  try {
    // `fs.realpathSync.native` somehow is the only thing that can consistently
    // normalize 8.3 "short names" in Windows to their long equivalents.
    if (typeof fs.realpathSync.native === 'function') {
      return fs.realpathSync.native(unrealPath)
    }
    return fs.realpathSync(unrealPath)
  } catch (e) {
    return unrealPath
  }
}

// Returns the parent of `filePath`, or `null` when `filePath` is already a
// root and therefore has no parent.
//
// We ask `path.resolve` whether it can still move upward rather than trying to
// recognize root paths by their shape. Enumerating root *syntaxes* means every
// form we forget is an infinite loop in the callers below, and Windows has
// more of them than the obvious `C:\`: UNC shares (`\\server\share`) and
// device paths (`\\?\C:\`) among them. Resolving to the same path we
// started from is the general signal that we've hit the top, whatever the
// shape.
function parentPath (filePath) {
  const parent = path.resolve(filePath, '..')
  return parent === filePath ? null : parent
}

function openRepository (repositoryPath, search) {
  if (!fs.existsSync(repositoryPath)) return null
  const symlink = realpath(repositoryPath) !== repositoryPath
  repositoryPath = normalizePath(repositoryPath, false)

  const repository = new Repository(repositoryPath, search)
  if (repository.exists()) {
    repository.caseInsensitiveFs = fs.isCaseInsensitive()
    if (symlink) {
      const workingDirectory = repository.getWorkingDirectory()
      let parent = parentPath(repositoryPath)
      while (parent !== null) {
        if (pathsAreEqual(repositoryPath, workingDirectory, fs.isCaseInsensitive())) {
          repository.openedWorkingDirectory = repositoryPath
          break
        }
        repositoryPath = parent
        parent = parentPath(repositoryPath)
      }
    }
    return repository
  } else {
    return null
  }
}

function openSubmodules (repository) {
  repository.submodules = {}

  for (let relativePath of repository.getSubmodulePaths()) {
    if (relativePath) {
      const submodulePath = path.join(repository.getWorkingDirectory(), relativePath)
      const submoduleRepo = openRepository(submodulePath, false)
      if (submoduleRepo) {
        if (submoduleRepo.getPath() === repository.getPath()) {
          submoduleRepo.release()
        } else {
          openSubmodules(submoduleRepo)
          repository.submodules[relativePath] = submoduleRepo
        }
      }
    }
  }
}

exports.open = function (repositoryPath, search = true) {
  const repository = openRepository(repositoryPath, search)
  if (repository) openSubmodules(repository)
  return repository
}
