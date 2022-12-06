const parentPort = require('worker_threads').parentPort

const git = require('../src/git')

const repositoryPath = git.open(__dirname).getPath()
parentPort.postMessage(repositoryPath);
