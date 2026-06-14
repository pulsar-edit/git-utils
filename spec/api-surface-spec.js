const path = require('path')
const { Project } = require('ts-morph')

// Loading `../src/git` runs its side effects against the `Repository`
// constructor exported by the native addon — adding JS-level wrapper
// methods and deleting `getStatusForPath`. `require` caches modules, so
// requiring the addon afterwards returns the same (already-mutated)
// `Repository` constructor.
require('../src/git')
const { Repository } = require('../build/Release/git.node')

describe('the Repository API surface', () => {
  const project = new Project()
  const sourceFile = project.addSourceFileAtPath(
    path.join(__dirname, '../src/git.d.ts')
  )
  const repositoryClass = sourceFile.getClassOrThrow('Repository')

  const declaredMethods = new Set(
    repositoryClass.getInstanceMethods().map(method => method.getName())
  )

  const runtimeMethods = new Set(Object.getOwnPropertyNames(Repository.prototype))
  runtimeMethods.delete('constructor')

  it('documents every method exposed on Repository.prototype', () => {
    const undocumented = [...runtimeMethods].filter(name => !declaredMethods.has(name))
    expect(undocumented).toEqual([])
  })

  it('does not document methods that no longer exist on Repository.prototype', () => {
    const stale = [...declaredMethods].filter(name => !runtimeMethods.has(name))
    expect(stale).toEqual([])
  })
})
