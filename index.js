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
import expressWs from 'express-ws'
// import session from 'express-session'

const configFile = './agent.yml'
const configString = readFileSync(configFile, 'utf8')
const config = yaml.load(configString);
const baseUrl = config.constants.baseUrl.replace(/\/$/, '')  // omit trailing slash
const [scheme, empty, host, ...pathParts] = baseUrl.split('/')
let path = ''
if (pathParts.length) {
  path = `/${pathParts.join('/')}`
}
const messagingEndpoint = config.server.init[0]['$args'][0].messagingServiceEndpoint
const messagingPath = `${path}${messagingEndpoint}`
const sendPath = `${path}/send`

const myDidAlias = [host, ...pathParts].join(':')
const didDocPath = path.length == 0 ? '/.well-known/did.json' : `${path}/did.json`
const schemaPath = `${path}/open-api.json`

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

let myDid
let socket

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

async function createDID() {
  const did = await agent.didManagerCreate({ alias: myDidAlias }).catch(console.error)
  console.log(`New did ${myDidAlias} created`)
  const msgService = {
    "id": "#messaging",
    "type": "DIDCommMessaging",
    "serviceEndpoint": `${scheme}//${host}${messagingPath}`,
    "description": "Send and receive messages"
  }
  await agent.didManagerAddService({ did: did.did, service: msgService}).catch(console.error)
  did.services.push(msgService)

  const x2Key = await agent.keyManagerCreate({ kms: 'local', type: 'X25519' })
  await agent.didManagerAddKey({ did: did.did, key: x2Key }).catch(console.error)
  did.keys.push(x2Key)

  return did
}

function getDidDocument(req, res) {
  const contexts = new Set(['https://www.w3.org/ns/did/v1'])
  const verificationMethods = []
  const authentications = []
  const assertionMethods = []
  const didDoc = {
    "@context": [...contexts],
    "id": `did:web:${myDidAlias}`,
    "verificationMethod": [],
    "authentication": [],
    "assertionMethod": [],
    "keyAgreement": [],
    "service": myDid.services
  }
  for (const key of myDid.keys) {
    const keyId = `did:web:${myDidAlias}#${key.kid}`
    didDoc.verificationMethod.push({
      "id": keyId,
      "type": keyTypes[key.type],
      "controller": `did:web:${myDidAlias}`,
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
  res.json(didDoc)
}

async function sendMessage(req, res) {
  const message = req.query.message
  const thread = req.query.thread
  const fromDid = req.query.fromDid
  const toDid = req.query.toDid
  const now = new Date()
  const msgId = now.toISOString()
  // const didCommMsg = new Message({metaData: msg.metaData })
  const didCommMsg = new Message({})
  didCommMsg.id = msgId
  didCommMsg.created_time = now.getTime() // createdAt
  didCommMsg.thid = thread // threadId
  didCommMsg.type = 'Simple Chat'
  didCommMsg.from = fromDid
  didCommMsg.to = toDid
  didCommMsg.body = { content: message } // data
  console.log(didCommMsg)
  const packeddidCommMsg = await agent.packDIDCommMessage({
    packing: 'authcrypt',
    message: didCommMsg,
  })
  console.log(packeddidCommMsg)
  const result = await agent.sendDIDCommMessage({
    messageId: msgId,
    threadId: thread,
    packedMessage: packeddidCommMsg,
    recipientDidUrl: didCommMsg.to,
  })
  res.json(result)
}

async function receiveMessage(req, res) {
  let json
  let raw
  if (req.method == 'GET') {
    json = req.query
    raw = JSON.stringify(json)
  }
  else if (typeof(req.body) == typeof({})) {
    json = req.body
    raw = JSON.stringify(json)
  }
  else if (req.headers['content-type'].includes('text/plain')) {
    raw = req.body
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
    console.log(msg)
    if (socket) {
      socket.on('message', (reply) => {
        console.log(reply)
      })
      socket.send(JSON.stringify(msg))
      res.send('OK')
    }
    else {
      res.status(503).headers('Retry-After: 10').send('Websocket not yet listening. Please try again later!')
    }
    /*
    // await agent.dataStoreSaveMessage(msg)
    const now = new Date()
    const msgId = now.toISOString()
    const reply = new Message({metaData: msg.metaData })
    reply.id = msgId
    reply.createdAt = now.getTime()
    reply.threadId = msg.threadId
    reply.type = msg.type
    reply.data = { content: 'Viesti' }
    reply.from = msg.to
    reply.to = msg.from
    // console.log(reply)
    const packedReply = await agent.packDIDCommMessage({
      packing: 'authcrypt',
      message: reply,
    })
    const returnRouteResponse = msg?.metaData?.find((v) => v.type === 'ReturnRouteResponse')
    if (returnRouteResponse && returnRouteResponse.value) {
      const returnMessage = JSON.parse(returnRouteResponse.value)
      console.log('return path found:')
      console.log(returnMessage)
      const result = await agent.sendDIDCommMessage({
        messageId: msgId,
        packedReply,
        recipientDidUrl: msg.from,
      })
      // console.log(result)
      agent.emit('DIDCommV2Message-sent', returnMessage.id)
      res.json(returnMessage.message)
    } else if (msg) {
      res.contentType('text/plain').send(packedReply.message)
      console.log(`Responded with ${packedReply.message}`)
    }
    */
  }
  catch(e) {
    console.warn('Error parsing message')
    console.log(JSON.stringify(json, null, 1))
    console.error(e)
  }
}

async function setupSockets(ws, req) {
  socket = ws
}

const dids = await agent.didManagerFind({ alias: myDidAlias })
if (dids.length > 0) {
  myDid = dids[0]
}
else {
  myDid = await createDID().catch(console.error)
}

/*
const messagingRouter = MessagingRouter({
  metaData: { type: 'express' },
})
*/



const app = express()
expressWs(app)
app.set('trust proxy', 1)
app.use(cors())
app.use(bodyParser.json({type: didCommType}))
app.use(bodyParser.text({type: 'text/plain'}))
app.get(path, (req, res) => { res.json(agent.availableMethods()) })
app.post(messagingPath, receiveMessage)
app.get(messagingPath, receiveMessage)
app.get(sendPath, sendMessage)
app.get(didDocPath, getDidDocument)
app.ws('/', setupSockets)
var server = app.listen(httpPort, (err) => {
  if (err) { console.error(err) }
  console.log(`Server running on port ${httpPort}, public address ${baseUrl}`)
})

