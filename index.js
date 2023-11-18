import { createAgent } from '@veramo/core'
import { DIDManager } from '@veramo/did-manager'
import { KeyManager } from '@veramo/key-manager'
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { WebDIDProvider } from '@veramo/did-provider-web'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations } from '@veramo/data-store'
import { DataSource } from 'typeorm'
import { MessageHandler } from '@veramo/message-handler'
import { DIDCommMessageHandler } from '@veramo/did-comm'

const DATABASE_FILE = 'database.sqlite'
const KMS_SECRET_KEY = '192315f5fc731222950671b7bc39226c8b8b79b8a35274b6a3e34d808d22b153'

let myDid
const myDidAlias = 'samuelmr.github.io:difhack-company'

const dbConnection = new DataSource({
  type: 'sqlite',
  database: DATABASE_FILE,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['error', 'info', 'warn'],
  entities: Entities,
}).initialize()

export const agent = createAgent({
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
        'did:web': new WebDIDProvider({defaultKms: 'local'})
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...webDidResolver(),
      }),
    }),
  ],
})

async function createDID() {
  const did = await agent.didManagerCreate({ alias: myDidAlias })
  console.log(`New did ${myDidAlias} created`)
  console.log(JSON.stringify(did, null, 2))
  return did
}

myDid = await agent.didManagerFind({ alias: myDidAlias })
if (myDid.length == 0) {
  myDid = await createDID().catch(console.error)
}

const server = Bun.serve({
  port: 3000,
  async fetch(request) {
    return new Response(JSON.stringify(myDid))
  },
})

console.log(`Listening on localhost:${server.port}`)
