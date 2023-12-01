import { readFileSync } from 'node:fs'
import * as yaml from 'js-yaml'
import { createAgent } from '@veramo/core'
import { KeyManager } from '@veramo/key-manager'
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations } from '@veramo/data-store'
import { DataSource } from 'typeorm'
import { DIDManager } from '@veramo/did-manager'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key'
import { PeerDIDProvider, getResolver } from '@veramo/did-provider-peer'
import { WebDIDProvider } from '@veramo/did-provider-web'
import { MessageHandler, Message } from '@veramo/message-handler'
import { DIDComm, DIDCommMessageHandler } from '@veramo/did-comm'
// import { AgentRouter, ApiSchemaRouter, WebDidDocRouter, MessagingRouter, RequestWithAgentRouter } from '@veramo/remote-server'
import { bytesToBase58, bytesToMultibase, hexToBytes } from '@veramo/utils'
import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
// import session from 'express-session'
import { WebSocketServer } from 'ws';

// const multiUser = true
// const retries = 5

const configFile = './agent.yml'
const configString = readFileSync(configFile, 'utf8')
const config = yaml.load(configString);
const baseUrl = config.constants.baseUrl.replace(/\/$/, '')  // omit trailing slash
const [scheme, empty, host, ...pathParts] = baseUrl.split('/')
let path = ''
if (pathParts.length) {
  path = `/${pathParts.join('/')}`
}
const userPath = path + '/:user'
const messagingEndpoint = config.server.init[0]['$args'][0].messagingServiceEndpoint
const messagingPath = `${path}${messagingEndpoint}`
const userMessagingPath = `${userPath}${messagingEndpoint}`
const sendPath = `${path}/send`
const userSendPath = `${userPath}/send`
const wsPath = `${path}/ws`
const userWsPath = `${userPath}/ws`

const didDocPath = path.length == 0 ? '/.well-known/did.json' : `${path}/did.json`
const userDidDocPath = `${userPath}/did.json`
// const schemaPath = `${path}/open-api.json`

const httpPort = parseInt(config.constants.port)

const didCommType = 'application/didcomm-encrypted+json'

const DATABASE_FILE = config.constants.databaseFile
const KMS_SECRET_KEY = config.constants.dbEncryptionKey

// https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/remote-server/src/web-did-doc-router.ts#L17C46-L24C2
const keyTypes = {
  Secp256k1: 'EcdsaSecp256k1VerificationKey2019',
  Secp256r1: 'EcdsaSecp256r1VerificationKey2019',
  Ed25519: 'Ed25519VerificationKey2018',
  X25519: 'X25519KeyAgreementKey2019',
  Bls12381G1: 'Bls12381G1Key2020',
  Bls12381G2: 'Bls12381G2Key2020',
}

// let myDid
let server, sockets = {}

const dbConnection = new DataSource({
  type: 'sqlite',
  database: DATABASE_FILE,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['debug', 'error', 'info', 'warn'],
  entities: Entities,
}).initialize()

const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
      },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      defaultProvider: 'did:web',
      providers: {
        'did:key': new KeyDIDProvider({defaultKms: 'local'}),
        'did:peer': new PeerDIDProvider({defaultKms: 'local'}),
        'did:web': new WebDIDProvider({defaultKms: 'local'}),
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...getDidKeyResolver(),
        ...getResolver(),
        ...webDidResolver(),
      }),
    }),
    new MessageHandler({
      messageHandlers: [
        new DIDCommMessageHandler(),
        // new MyMessageHandler()
      ],
    }),
    new DIDComm()
  ],
})

async function createDID(alias) {
  const did = await agent.didManagerCreate({ alias: alias }).catch(console.error)
  console.log(`New did ${alias} created`)
  let msgEndPoint = `${scheme}//${host}${messagingPath}`
  if (alias.includes(':')) {
    msgEndPoint = `${scheme}//${host}${userMessagingPath}`.replace(':user', alias.split(':').pop())
  }
  const msgService = {
    "id": `did:web:${alias}#messaging`,
    "type": "DIDCommMessaging",
    "serviceEndpoint": msgEndPoint,
    "description": "Send and receive messages"
  }
  await agent.didManagerAddService({ did: did.did, service: msgService}).catch(console.error)
  did.services.push(msgService)
  const x2Key = await agent.keyManagerCreate({ kms: 'local', type: 'X25519' })
  await agent.didManagerAddKey({ did: did.did, key: x2Key }).catch(console.error)
  did.keys.push(x2Key)
  return did
}

async function getMyDid(user) {
  let alias = [host, ...pathParts].join(':')
  let did
  if (user) {
    alias += `:${user}`
  }
  const dids = await agent.didManagerFind({ alias: alias })
  if (dids.length > 0) {
    did = dids[0]
  }
  else {
    did = await createDID(alias).catch(console.error)
  }
  return { alias, did}
}
async function getDidDocument(req, res) {
  const {alias, did} = await getMyDid(req.params.user)
  const contexts = new Set(['https://www.w3.org/ns/did/v1'])
  const verificationMethods = []
  const authentications = []
  const assertionMethods = []
  const didDoc = {
    "@context": [...contexts],
    "id": `did:web:${alias}`,
    "verificationMethod": [],
    "authentication": [],
    "assertionMethod": [],
    "keyAgreement": [],
    "service": did.services
  }
  for (const key of did.keys) {
    const keyId = `did:web:${alias}#${key.kid}`
    didDoc.verificationMethod.push({
      "id": keyId,
      "type": keyTypes[key.type],
      "controller": `did:web:${alias}`,
      "publicKeyHex": key.publicKeyHex
    })
    if (key.type == 'X25519') {
      didDoc.keyAgreement.push(keyId)
    }
    else {
      didDoc.authentication.push(keyId)
      didDoc.assertionMethod.push(keyId)
    }
    // from https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/remote-server/src/web-did-doc-router.ts#L44C3-L110C4
    switch (didDoc.verificationMethod.at(-1).type) {
      case 'EcdsaSecp256k1VerificationKey2019':
      case 'EcdsaSecp256k1RecoveryMethod2020':
        contexts.add('https://w3id.org/security/v2')
        contexts.add('https://w3id.org/security/suites/secp256k1recovery-2020/v2')
        break
      case 'Ed25519VerificationKey2018':
        contexts.add('https://w3id.org/security/suites/ed25519-2018/v1')
        didDoc.verificationMethod.at(-1).publicKeyBase58 = bytesToBase58(hexToBytes(key.publicKeyHex))
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'X25519KeyAgreementKey2019':
        contexts.add('https://w3id.org/security/suites/x25519-2019/v1')
        didDoc.verificationMethod.at(-1).publicKeyBase58 = bytesToBase58(hexToBytes(key.publicKeyHex))
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'Ed25519VerificationKey2020':
        contexts.add('https://w3id.org/security/suites/ed25519-2020/v1')
        didDoc.verificationMethod.at(-1).publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'base58btc', 'ed25519-pub')
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'X25519KeyAgreementKey2020':
        contexts.add('https://w3id.org/security/suites/x25519-2020/v1')
        didDoc.verificationMethod.at(-1).publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'base58btc', 'x25519-pub')
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'EcdsaSecp256r1VerificationKey2019':
        contexts.add('https://w3id.org/security/v2')
        break
      case 'Bls12381G1Key2020':
      case 'Bls12381G2Key2020':
        contexts.add('https://w3id.org/security/bbs/v1')
        break
      default:
        break
    }
  }
  didDoc['@context'] = [...contexts]
  // console.log(didDoc)
  res.json(didDoc)
}

async function sendDidCommMessage(fromDid, toDid, thread, message) {
  const now = new Date()
  const msgId = now.toISOString()
  const didCommMsg = {
    id: msgId,
    created_time: now.getTime(), // createdAt
    thid: thread, // threadId
    type: 'Simple Chat',
    from: fromDid,
    to: toDid,
    body: { content: message }, // data
  }
  console.log(didCommMsg)
  try {
    const packeddidCommMsg = await agent.packDIDCommMessage({
      packing: 'authcrypt',
      message: didCommMsg,
    })
    // console.log(packeddidCommMsg)
    const result = await agent.sendDIDCommMessage({
      messageId: msgId,
      threadId: thread,
      packedMessage: packeddidCommMsg,
      recipientDidUrl: didCommMsg.to,
    })
    console.log(`Message sent to ${toDid}`)
    return result
  }
  catch (e) {
    console.error(e)
    return false
  }
}

async function sendMessageHTTP(req, res) {
  const { alias, did } = await getMyDid(req.params.user)
  const fromDid = `did:web:${alias}`
  const toDid = req.query.toDid
  const message = req.query.message
  const thread = req.query.thread
  const result = sendDidCommMessage(fromDid, toDid, thread, message)
  if (!result) {
    res.status(500).send('Could not send message.')
  }
  console.log(`Sent message to ${toDid}`)
  res.json(result)
}

async function receiveMessage(req, res) {
  let user = ''
  if (multiUser) {
    user = req.url.replace(messagingEndpoint, '').replace('/', '')
  }
  // creates users if they don't exist yet  :)
  const { alias, did } = await getMyDid(user)
  const socket = sockets[alias]
  let json = req.body
  let raw = req.body
  if (req.method == 'GET') {
    json = req.query
    raw = JSON.stringify(json)
  }
  else if (typeof(req.body) == typeof({})) {
    json = req.body
    raw = JSON.stringify(json)
  }
  // else if (req.headers['content-type'].includes('text/plain')) {
  else {
    try {
      json = JSON.parse(raw)
    }
    catch(e) {
      console.warn('Invalid JSON')
      console.log(req.body)
      console.error(e)
      res.json(e)
    }
  }
  try {
    const msg = await agent.handleMessage({raw: raw})
    // console.log(msg)
    if (socket) {
      // socket.send(JSON.stringify(msg.data.content))
      socket.send(msg.data.content)
      res.send('OK')
      console.log('Relayed to websocket')
    }
    else {
      console.log(`No socket for ${alias}`)
      res.set('Retry-After: 10').status(503).send('Websocket not yet listening. Please try again later!')
      console.log('Could not relay to websocket')
    }
  }
  catch(e) {
    console.warn('Error parsing message')
    console.log(JSON.stringify(json, null, 1))
    console.error(e)
  }
  await agent.dataStoreSaveMessage(msg).catch(console.error)
  console.log(`Message ${msg.id} saved`)
}

const app = express()
app.set('trust proxy', 1)
app.use(cors())
app.use((req, res, next) => {
  console.log(req.method, req.url)
  next()
})
app.use(bodyParser.json({type: didCommType}))
app.use(bodyParser.text({type: 'text/plain'}))
// app.get(path, (req, res) => { res.json(agent.availableMethods()) })
app.get('/favicon.ico', (req, res) => {
  res.sendFile(new URL('./favicon.ico', import.meta.url).pathname)
})
app.get(path, (req, res) => {
  res.sendFile(new URL('./operator.html', import.meta.url).pathname)
})
app.get(userPath, (req, res) => {
  res.sendFile(new URL('./index.html', import.meta.url).pathname)
})
app.post(messagingPath, receiveMessage)
app.post(userMessagingPath, receiveMessage)
// app.get(messagingPath, receiveMessage)
app.get(sendPath, sendMessageHTTP)
app.get(userSendPath, sendMessageHTTP)
app.get(didDocPath, getDidDocument)
app.get(userDidDocPath, getDidDocument)
// app.get(wsPath, (req, res) => {console.log(req.headers); res.set('Upgrade: websocket').set('Connection: upgrade').sendStatus(101)})
server = app.listen(httpPort, (err) => {
  if (err) { console.error(err) }
  console.log(`Server running on port ${httpPort}, public address ${baseUrl}`)
})
server.on('upgrade', setupSocket)

function heartbeat() {
  this.isAlive = true;
}
async function setupSocket(req, socket, head) {
  let user = '' // even empty string can be used as an object key
  if (req.url != path) {
    user = req.url.replace('/', '')
  }
  const { alias, did } = await getMyDid(user)

  const wsServer = new WebSocketServer({ noServer: true })
  wsServer.on('connection', function connection(ws) {
    sockets[alias] = ws
    ws.isAlive = true;
    ws.on('error', console.error)
    ws.on('pong', heartbeat)
    ws.on('message', async (data) => {
      // console.log(typeof data)
      if (data.toString().toLowerCase() == "ping") {
        // console.log('Got ping')
        ws.send("pong")
        return
      }
      console.log(data.toString())
      let json
      try {
        json = JSON.parse(data.toString())
      }
      catch(e) {
        console.error('Could not parse JSON!')
        console.log(data)
        ws.send('Error')
        return
      }
      const { toDid, message, thread } = json
      const fromDid = `did:web:${alias}`
      try {
        const result = await sendDidCommMessage(fromDid, toDid, thread, message)
      }
      catch(e) {
        console.error(e)
      }
    })
  })
  const interval = setInterval(function ping() {
    wsServer.clients.forEach(function each(ws) {
      if (ws.isAlive === false) return ws.terminate()
      ws.isAlive = false
      ws.ping()
    })
  }, 30000)
  wsServer.on('close', function close() {
    clearInterval(interval);
  });
  console.log(`Initiated websocket server for ${alias}`)
  wsServer.handleUpgrade(req, socket, head, (ws) => {
    console.log(`Handling upgrade for ${alias}`)
    wsServer.emit('connection', ws, req)
  })
}
