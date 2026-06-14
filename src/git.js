// @ts-check
const path = require('path')
const fs = require('fs-plus')

/**
 * @template T
 * @typedef {(err: Error | null, result: T) => void} NodeCallback
 */

/** @type {{ Repository: typeof import('./git').Repository }} */
// @ts-expect-error
const bundle = require('../build/Release/git.node')
const { Repository } = bundle

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
  if (!pathA.includes('~') && !pathB.includes('~')) {
    return result
  }

  // If we get this far, we're on Windows and comparing two paths, at least one
  // of which contains an 8.3 short name. The only obvious and reliable way to
  // address this is to `statSync` both paths and verify their IDs are the
  // same.
  if (!fs.existsSync(pathA) || !fs.existsSync(pathB)) {
    return result
  }
  let statA = fs.statSync(pathA)
  let statB = fs.statSync(pathB)

  return statA.ino === statB.ino && statA.dev === statB.dev
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
  let workingDirectory
  if (!filePath) return filePath
  filePath = realpathRecursive(filePath)

  if (!IS_WINDOWS && filePath[0] !== '/') {
    return filePath
  }

  workingDirectory = this.getWorkingDirectory()
  if (workingDirectory) {
    if (pathStartsWith(filePath, workingDirectory, this.caseInsensitiveFs, false)) {
      return filePath.substring(workingDirectory.length + 1)
    } else if (pathsAreEqual(filePath, workingDirectory, this.caseInsensitiveFs, false)) {
      return ''
    }
  }

  if (this.openedWorkingDirectory) {
    workingDirectory = this.openedWorkingDirectory
    if (pathStartsWith(filePath, workingDirectory, this.caseInsensitiveFs, false)) {
      return filePath.substring(workingDirectory.length + 1)
    } else if (pathsAreEqual(filePath, workingDirectory, this.caseInsensitiveFs, false)) {
      return ''
    }
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

/**
 * @typedef {import('./git.js').Repository & { getStatusForPath(path: string): number }} RepositoryProto
 */
const repositoryProto = /** @type {RepositoryProto} */ (Repository.prototype)
const {getHeadAsync, getStatus, getStatusAsync, getStatusForPath} = repositoryProto

// We don't document `getStatusForPath` because it's used only internally. But
// that means TypeScript gets confused when we try to delete it.
// @ts-expect-error
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

/**
 * @template T
 * @param {import('./git.js').Repository} repo
 * @param {(done: NodeCallback<T>) => void} rawFn
 * @returns {Promise<T>}
 */
function performAsyncWork (repo, rawFn) {
  let fn = promisify(rawFn)

  let result = repo._lastAsyncPromise
    ? repo._lastAsyncPromise.then(fn, fn)
    : fn()

  repo._lastAsyncPromise = result
  return result
}

/**
 * @template T
 * @param {(cb: NodeCallback<T>) => void} fn
 * @returns {() => Promise<T>}
 */
function promisify (fn) {
  let promisified = () => {
    /** @type {Promise<T>} */
    let p = new Promise((resolve, reject) =>
      fn((error, result) => error ? reject(error) : resolve(result))
    )
    return p
  }
  return promisified
}

/**
 * Given `unrealPath` — which may or may not exist on disk in its current form
 * — resolve to a real path on disk, if possible.
 *
 * This is done by traversing upward to the first directory that _does_ exist,
 * then getting its `realpath` and appending the rest back on.
 *
 * @param {string} unrealPath
 * @returns {string}
 */
function realpathRecursive (unrealPath) {
  let currentPath = unrealPath
  let result = unrealPath
  let remainder = ''
  if (!path.isAbsolute(unrealPath)) {
    return realpath(unrealPath)
  }
  while (!isRootPath(currentPath)) {
    try {
      result = fs.realpathSync.native(currentPath)
      break
    } catch (e) {
      if (e.message.includes('ENOENT')) {
        currentPath = path.resolve(currentPath, '..')
        remainder = path.relative(currentPath, unrealPath)
      } else {
        return unrealPath
      }
    }
  }
  if (isRootPath(currentPath)) {
    return unrealPath
  }
  let finalResult = trimPath(`${result}/${remainder}`)
  return normalizePath(finalResult)
}

/**
 * Trim a trailing separator from a path.
 * @param {string} filePath
 * @returns {string}
 */
function trimPath (filePath) {
  if (!filePath.endsWith('/')) return filePath
  return filePath.replace(/\/$/, '')
}

/**
 * Attempt to resolve a path to its real path on disk; if it fails, returns the
 * original path.
 * @param {string} unrealPath
 * @returns {string}
 */
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

/**
 * Check whether the given path is the root — i.e., has no parent directory.
 * @param {string} repositoryPath
 * @returns {boolean}
 */
function isRootPath (repositoryPath) {
  if (IS_WINDOWS) {
    return /^[a-zA-Z]+:[\\/]$/.test(repositoryPath)
  } else {
    return repositoryPath === path.sep
  }
}

/**
 * @param {string} repositoryPath
 * @param {boolean} search
 * @returns {import('./git.js').Repository | null}
 */
function openRepository (repositoryPath, search) {
  if (!fs.existsSync(repositoryPath)) return null
  const symlink = realpath(repositoryPath) !== repositoryPath
  repositoryPath = normalizePath(repositoryPath, false)

  const repository = new Repository(repositoryPath, search)
  if (repository.exists()) {
    repository.caseInsensitiveFs = fs.isCaseInsensitive()
    if (symlink) {
      const workingDirectory = repository.getWorkingDirectory()
      while (!isRootPath(repositoryPath)) {
        if (pathsAreEqual(repositoryPath, workingDirectory, fs.isCaseInsensitive())) {
          repository.openedWorkingDirectory = repositoryPath
          break
        }
        repositoryPath = path.resolve(repositoryPath, '..')
      }
    }
    return repository
  } else {
    return null
  }
}

/**
 * @param {import('./git.js').Repository} repository
 * @returns {void}
 */
function openSubmodules (repository) {
  repository.submodules = {}

  for (let relativePath of repository.getSubmodulePaths()) {
    if (relativePath) {
      let workingDirectory = repository.getWorkingDirectory()
      if (!workingDirectory) throw new Error('Invalid repository')
      const submodulePath = path.join(workingDirectory, relativePath)
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

/** @type {typeof import('./git.js').open} */
exports.open = function (repositoryPath, search = true) {
  const repository = openRepository(repositoryPath, search)
  if (repository) openSubmodules(repository)
  return repository
}
