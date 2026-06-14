/** Metadata for methods that compare two references. */
export interface AheadBehind {
  ahead: number;
  behind: number;
}

/** Metadata for diffs between two references. */
export interface AddedDeleted {
  added: number;
  deleted: number;
}

/**
 * Options for {@link Repository#getLineDiffs} and
 * {@link Repository#getLineDiffDetails}.
 */
export interface GetLineDiffsOptions {
  /** Whether to ignore changes in whitespace at the end of lines. */
  ignoreSpaceAtEOL: boolean;

  /** Alias of {@link GetLineDiffsOptions.ignoreSpaceAtEOL}. */
  ignoreEolWhitespace: boolean;

  /**
   * Whether to ignore changes in the amount of whitespace. This ignores
   * whitespace at line end (like `ignoreSpaceAtEOL`) and also considers
   * all other sequences of one or more whitespace characters to be equivalent.
   */
  ignoreSpaceChange: boolean;

  /**
   * Whether to ignore whitespace when comparing lines. This goes further than
   * `ignoreSpaceChange` — ignoring space differences even if one line has
   * whitespace while the other has none.
   */
  ignoreAllSpace: boolean;

  /**
   * Whether to compare against the index version instead of the HEAD version.
   */
  useIndex: boolean;
}

/** An object returned by {@link Repository#getLineDiffs}. */
export interface LineDiff {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
}

/** An object returned by {@link Repository#getLineDiffDetails}. */
export interface LineDiffDetail extends LineDiff {
  /**
   * This line's old line number, or `-1` if the line is not present in the old
   * version.
   */
  oldLineNumber: number;

  /**
   * This line's new line number, or `-1` if the line is not present in the new
   * version.
   */
  newLineNumber: number;

  /** The content of the line. */
  line: string;
}

/**
 * A single reference as returned by {@link Repository.getReferences}.
 */
export interface Reference {
  heads: string[];
  remotes: string[];
  tags: string[];
}

export class Repository {
  /** @private */
  constructor(path: string, search?: boolean);

  /**
   * Checks whether this repository currently exists.
   *
   * @returns `true` if the instance still refers to a valid repository;
   *  `false` if the path on disk no longer exists or is no longer a
   *  repository.
   */
  exists(): boolean;

  /**
   * Get the reference or SHA-1 that HEAD points to such as `refs/heads/master`
   * or a full SHA-1 if the repository is in a detached HEAD state.
   *
   * @returns The string reference name or SHA-1.
   */
  getHead(): string | null;

  /**
   * Get the reference or SHA-1 that HEAD points to such as `refs/heads/master`
   * or a full SHA-1 if the repository is in a detached HEAD state.
   *
   * @returns A promise that resolves with the string reference name or SHA-1.
   */
  getHeadAsync(): Promise<string | null>;

  /**
   * Get the number of commits ahead/behind the local branch is compared to the
   * remote branch that it tracks. Similar to the commit numbers reported by
   * `git status` when a remote tracking branch exists.
   *
   * @param branch The branch name to look up; defaults to `HEAD`.
   * @returns An object with `ahead` and `behind` keys whose values are
   *  integers that will always be greater than or equal to 0.
   */
  getAheadBehindCount(branch?: string): AheadBehind;

  /**
   * Get the number of commits ahead/behind the local branch is compared to the
   * remote branch that it tracks. Similar to the commit numbers reported by
   * `git status` when a remote tracking branch exists.
   *
   * @param branch The branch name to look up; defaults to `HEAD`.
   * @returns A `Promise` returning an object with `ahead` and `behind` keys
   *  whose values are integers that will always be greater than or equal to 0.
   */
  getAheadBehindCountAsync(branch?: string): Promise<AheadBehind>;

  /**
   * Get the status of a single path or all paths in the repository. This will
   * not include ignored paths.
   *
   * @returns An object with paths as keys and integer statuses as values.
   */
  getStatus(): Record<string, number>;

  /**
   * Get the status of a single path or all paths in the repository. This will
   * not include ignored paths.
   *
   * @param filePath An optional path (relative to the repository root) if you
   *  want to retrieve only a single status.
   * @returns An integer status.
   */
  getStatus(filePath: string): number;

  /**
   * Get the status of a single path or all paths in the repository. This will
   * not include ignored paths.
   *
   * @returns A promise that resolves with an object with paths as keys and
   *  integer statuses as values.
   */
  getStatusAsync(): Promise<Record<string, number>>;

  /**
   * Get the status of a single path or all paths in the repository. This will
   * not include ignored paths.
   *
   * @param filePath An optional path (relative to the repository root) if you
   *  want to retrieve only a single status.
   * @returns A promise that resolves with an integer status.
   */
  getStatusAsync(filePath: string): Promise<number>;

  /**
   * Given a list of paths to files in the repository, returns the statuses of
   * each.
   *
   * @param paths A list of paths (relative to the repository root).
   * @returns An object whose keys are paths and whose values are status
   *  integers.
   */
  getStatusForPaths(paths: []): Record<string, number>;

  /**
   * Given a list of paths to files in the repository, returns the statuses of
   * each.
   *
   * @param paths A list of paths (relative to the repository root).
   * @returns An promise that resolves with an object whose keys are paths and
   *  whose values are status integers.
   */
  getStatusForPathsAsync(paths: []): Promise<Record<string, number>>;

  /**
   * Release the repository and close all file handles it has open. No other
   * methods can be called on the `Repository` object once it has been
   * released.
   */
  release(): void;

  /**
   * Get the working directory of the repository.
   */
  getWorkingDirectory(): string | null;

  /**
   * Restore the contents of a path in the working directory and index to the
   * version at HEAD. Similar to running `git reset HEAD -- <path>` and then a
   * `git checkout HEAD -- <path>`.
   *
   * @param path The path to checkout; must be relative to the repository root.
   * @returns `true` if the checkout was successful; `false` otherwise.
   */
  checkoutHead(path: string): boolean;

  /**
   * Check out a branch in this repository.
   *
   * @param reference The reference to check out.
   * @param create If `true`, creates the new reference if it doesn't exist;
   *  defaults to `false`.
   * @returns `true` if the checkout was successful; `false` otherwise.
   */
  checkoutReference(reference: string, create?: boolean): boolean;

  /**
   * @private Prefer {@link checkoutReference}.
   */
  checkoutRef(reference: string, create?: boolean): boolean;

  /**
   * Get the config value of the given key.
   *
   * @param key The string key for which to retrieve the value.
   * @returns The configuration value if it exists; `null` otherwise.
   */
  getConfigValue(key: string): string | null;

  /**
   * Set the config value of the given key.
   *
   * @param key The string key to set in the config.
   * @param value The string value to set in the config for the given key.
   * @returns `true` if setting the config value was successful; `false`
   *  otherwise.
   */
  setConfigValue(key: string, value: string): boolean;

  /**
   * Get the number of lines added and removed comparing the working directory
   * contents of the given path to the HEAD version of the given path.
   *
   * @param path The path to diff; must be relative to the repository root.
   * @returns An object with `added` and `deleted` keys whose values are
   *  integers (>= 0).
   */
  getDiffStats(path: string): AddedDeleted;

  /**
   * Get the blob contents of the given path at HEAD.
   *
   * Similar to `git show HEAD:<path>`.
   *
   * @param path The path; must be relative to the repository root.
   * @returns The string contents of the HEAD version of the path.
   */
  getHeadBlob(path: string): string;

  /**
   * Get the blob contents of the given path in the index.
   *
   * Similar to `git show :<path>`.
   *
   * @param path The path; must be relative to the repository root.
   * @returns The string contents of the index version of the path.
   */
  getIndexBlob(path: string): string;

  /**
   * Get the line diffs comparing the HEAD version of the given path to the
   * given text.
   *
   * @param path The path; must be relative to the repository root.
   * @param text The string text against which to diff the HEAD contents of the
   *  path. This will typically be the entire string contents of the file at
   *  `path`.
   * @param options An optional {@link GetLineDiffsOptions} object.
   * @returns An array of {@link LineDiff}s, or else `null` if none exist.
   */
  getLineDiffs(path: string, text: string, options?: GetLineDiffsOptions): LineDiff[] | null;

  /**
   * Get the line diff details comparing the HEAD version of the given path
   * to the given text. This returns more metadata than {@link getLineDiffs}.
   *
   * @param path The path; must be relative to the repository root.
   * @param text The string text against which to diff the HEAD contents of the
   *  path. This will typically be the entire string contents of the file at
   *  `path`.
   * @param options An optional {@link GetLineDiffsOptions} object.
   * @returns An array of {@link LineDiffDetail}s, or else `null` if none
   *  exist.
   */
  getLineDiffDetails(path: string, text: string, options?: GetLineDiffsOptions): LineDiffDetail[] | null;

  /**
   * Get the path of the repository.
   *
   * @returns The string absolute path of the opened repository.
   */
  getPath(): string;

  /**
   * Get all the local and remote references.
   *
   * @returns A {@link Reference} object.
   */
  getReferences(): Reference;

  /**
   * Get the target of the given reference.
   *
   * @param ref The string reference.
   * @returns The string target of the given reference.
   */
  getReferenceTarget(ref: string): string;

  /**
   * Get the branch that a remote's `HEAD` points to — i.e., the remote's
   * default branch. This is the equivalent of `git symbolic-ref
   * refs/remotes/<remoteName>/HEAD`.
   *
   * @param remoteName The string name of the remote; defaults to `origin`.
   * @returns The string reference name — e.g., `refs/remotes/origin/master` —
   *  or `null` if the remote has no HEAD reference.
   */
  getRemoteHead(remoteName?: string): string;

  /**
   * Get a possibly shortened version of the value returned by {@link getHead}.
   * This will remove leading segments of `refs/heads`, `refs/tags`, or
   * `refs/remotes` and will also shorten the SHA-1 of a detached HEAD to 7
   * characters.
   *
   * @returns A shortened reference name or SHA-1.
   */
  getShortHead(): string | null;

  /**
   * Get the name of the reference that a symbolic reference points to, without
   * resolving it any further. This is the equivalent of `git symbolic-ref
   * <ref>`.
   *
   * @param ref The string reference.
   * @returns Returns the string name of the reference that `ref` points to; or
   *  `null` if `ref` does not exist or is not a symbolic reference.
   */
  getSymbolicRefTarget(ref: string): string;

  /**
   * Get the upstream branch of the given branch.
   *
   * @param branch The branch to find the upstream branch of; defaults to
   *  `HEAD`.
   * @returns The upstream branch reference name, or `null` if none exists.
   */
  getUpstreamBranch(branch?: string): string | null;

  /**
   * Get the ignored status of a given path.
   *
   * @param path The path to the file; must be relative to the repository root.
   * @returns `true` if the path is ignored; `false` otherwise.
   */
  isIgnored (path: string): boolean;

  /**
   * Get the modified status of a given path.
   *
   * @param path The path to the file; must be relative to the repository root.
   * @returns `true` if the path is modified; `false` otherwise.
   */
  isPathModified(path: string): boolean;

  /**
   * Get the deleted status of a given path.
   *
   * @param path The path to check; must be relative to the repository root.
   * @returns `true` if the path is deleted; `false` otherwise.
   */
  isPathDeleted(path: string): boolean;

  /**
   * Get the new status of a given path.
   *
   * @param path The path to the file; must be relative to the repository root.
   * @returns `true` if the path is new; `false` otherwise.
   */
  isPathNew(path: string): boolean;

  /**
   * Get the staged status of a given path.
   *
   * @param path The path to the file; must be relative to the repository root.
   * @returns `true` if the path is staged in the index; `false` otherwise.
   */
  isPathStaged(path: string): boolean;

  /**
   * Check if a status value represents an ignored path.
   *
   * @param status The status value.
   * @returns `true` if the status is an ignored status; `false` otherwise.
   */
  isStatusIgnored(status: number): boolean;

  /**
   * Check if a status value represents a new path.
   *
   * @param status The status value.
   * @returns `true` if the status is a new status; `false` otherwise.
   */
  isStatusNew(status: number): boolean;

  /**
   * Check if a status value represents a deleted path.
   *
   * @param status The status value.
   * @returns `true` if the status is a deleted status; `false` otherwise.
   */
  isStatusDeleted(status: number): boolean;

  /**
   * Check if a status value represents a changed file that is staged in the
   * index.
   *
   * @param status The status value.
   * @returns `true` if the status is a staged status; `false` otherwise.
   */
  isStatusStaged(status: number): boolean;

  /**
   * Check if a status value represents a modified path.
   *
   * @param status The status value.
   * @returns `true` if the status is a modified status; `false` otherwise.
   */
  isStatusModified(status: number): boolean;

  /**
   * Check if the path is a submodule in the index.
   *
   * @param path The path to the file; must be relative to the repository root.
   * @returns `true` if the path is a submodule; `false` otherwise.
   */
  isSubmodule(path: string): boolean;

  /**
   * Reread the index to update any values that have changed since the last
   * time the index was read.
   */
  refreshIndex(): void;

  /**
   * Relativize the given path to the repository's working directory.
   * @param path The absolute path to relativize.
   * @returns A repository-relative path _if_ the given path descends from this
   *  repository's root; otherwise returns the given path.
   */
  relativize(path: string): boolean;

  /**
   * Checks if the given path is the repository's working directory.
   *
   * It is better to call this method than comparing a path directly against
   * the value of {@link getWorkingDirectory} since this method handles slash
   * normalization on Windows, case-insensitive filesystems, and symlinked
   * repositories.
   *
   * @param path The path to check.
   * @returns `true` if the given path is the repository's working directory;
   *  `false` otherwise.
   */
  isWorkingDirectory(path: string): boolean;

  /**
   * Get the repository for the submodule within which the path is located.
   *
   * @param path The path to the submodule; may be absolute or relative to the
   *  repository root.
   * @returns A {@link Repository}; or `null` if the path isn’t within a
   *  submodule.
   */
  submoduleForPath(path: string): Repository | null;

  /**
   * Get the paths of any submodules declared in this repository.
   *
   * @returns An array of paths that are relative to the repository root.
   */
  getSubmodulePaths(): string[];

  /**
   * Stage the changes in `path` into the repository's index. Clear any
   * conflict state associated with `path`.
   *
   * Raises an {@link Error} if the path isn't readable or if another exception
   * occurs.
   *
   * @param path The path to the file whose stages should be changed; must be
   *  relative to the repository root.
   */
  add(path: string): void;

  /**
   * Get the number of commits ahead/behind one branch is when compared to the
   * other branch. Similar to the commit numbers reported by `git status` when
   * a remote tracking branch exists.
   *
   * @param commitA The first commit SHA-1 to compare.
   * @param commitB The second commit SHA-1 to compare.
   * @returns An object with `ahead` and `behind` keys whose values are
   *  integers that will always be greater than or equal to 0.
   */
  compareCommits(commitA: string, commitB: string): AheadBehind;

  /** @private */
  compareCommitsAsync(done: (error: Error | null, result: AheadBehind) => void, commitA: string, commitB: string): Promise<AheadBehind>;

  /** @private */
  workingDirectory: string | null;

  /** @private */
  _getWorkingDirectory(): string | null;

  /** @private */
  _release(): void;

  /** @private */
  submodules: Record<string, Repository>;

  /** @internal */
  _lastAsyncPromise?: Promise<unknown>;

  /** @private */
  caseInsensitiveFs?: boolean;

  /** @private */
  openedWorkingDirectory?: string;
}

/**
 * Open the repository at the given path. This will return `null` if the
 * repository at the given path does not exist or cannot be opened.
 *
 * @param repositoryPath The path from which to try to open a repository.
 * @param search Whether to traverse upward from the given path until we find a
 *  repository.
 * @returns A {@link Repository} if one was found; `null` otherwise.
 */
export function open(repositoryPath: string, search?: boolean): Repository | null
