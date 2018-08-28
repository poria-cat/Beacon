
/**
 * 第一步： 初始化一些阈值组，进程，
 * 将进程组随机放入不同的阈值组，以0做第一个
 * 生成区块的阈值组并构建创世区块，
 * 第二步：运行DKG分布式签名算法计算出beaconSig，
 * 注： 当阈值组选完时，第一步和第二步并行运行
 * 第三步：将beaconSig对阈值组个数作模运算，所得结果为下一个
 * 接力的阈值组
 */
const crypto = require('crypto')
const _ = require('lodash')
const bls = require('bls-lib')
const dkg = require('dkg')
const bignum = require('bignum')
const nacl = require('tweetnacl')

const m = 10
const n = 10
const k = 6

const GroupList = {}
let ProcessList = []
let ProcessListStore = []
const keypairStore = {}
let blockHeight = 0
const chain = {}

function randRange(min, max) {
    return min + Math.floor(Math.random() * (max - min))
}

function addKeypair(ProcessList) {
    ProcessList.forEach(item => {
        const keys = nacl.sign.keyPair()
        const sk = Buffer.from(keys.secretKey).toString('hex')
        const pk = Buffer.from(keys.publicKey).toString('hex')
        keypairStore[item] = {
            sk, pk
        }
    })
}

function init() {
    // init Group
    for (let i = 0; i < m; i++) {
        GroupList[i] = []
    }
    // init progress
    for (let i = 0; i < m * n; i++) {
        crypto.getRandomValues = crypto.randomFillSync
        let randomId = crypto.getRandomValues(new Uint8Array(3))

        ProcessList.push(parseInt(Buffer.from(randomId).toString('hex'), 16))
        ProcessListStore.push(parseInt(Buffer.from(randomId).toString('hex'), 16))
    }

    // add Progress to Groups 

    for (let i = 0; i < m; i++) {
        const group = GroupList[i]
        for (let j = 0; j < n; j++) {
            let progressSize = ProcessList.length
            let processIndex = randRange(0, progressSize)
            group.push(ProcessList[processIndex])
            ProcessList = _.pull(ProcessList, ProcessList[processIndex])
        }
    }
}

function generateBeaconSig(gruop, threshold, msg) {
    return new Promise((resolve, reject) => {
        bls.onModuleInit(() => {
            bls.init()
            const members = gruop.map(id => {
                const sk = bls.secretKey()
                bls.hashToSecretKey(sk, Buffer.from([id]))
                return {
                    id: sk,
                    recievedShares: []
                }
            })
            const vvecs = []

            members.forEach(id => {
                const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, members.map(m => m.id), threshold)
                vvecs.push(verificationVector)
                secretKeyContribution.forEach((sk, i) => {
                    const member = members[i]
                    const verified = dkg.verifyContributionShare(bls, member.id, sk, verificationVector)
                    if (!verified) {
                        throw new Error('invalid share!')
                    }
                    member.recievedShares.push(sk)
                })
            })


            members.forEach((member, i) => {
                const sk = dkg.addContributionShares(bls, member.recievedShares)
                member.secretKeyShare = sk
            })
            const groupsVvec = dkg.addVerificationVectors(bls, vvecs)

            const groupsPublicKey = groupsVvec[0]
            const sigs = []
            const signersIds = []
            for (let i = 0; i < threshold; i++) {
                const sig = bls.signature()
                bls.sign(sig, members[i].secretKeyShare, msg)
                sigs.push(sig)
                signersIds.push(members[i].id)
            }

            const groupsSig = bls.signature()
            bls.signatureRecover(groupsSig, sigs, signersIds)

            const sigArray = bls.signatureExport(groupsSig)
            const sigBuf = Buffer.from(sigArray)

            var verified = bls.verify(groupsSig, groupsPublicKey, msg)
            bls.free(groupsSig)

            bls.freeArray(groupsVvec)
            members.forEach(m => {
                bls.free(m.secretKeyShare)
                bls.free(m.id)
            })
            resolve({ verified: Boolean(verified), signature: sigBuf.toString('hex') })
        })
    })
}

function shuffle(seed, process) {
    var truncDelegateList = process;
    var currentSeed = Buffer.from(seed)
    for (var i = 0, delCount = truncDelegateList.length; i < delCount; i++) {
        for (var x = 0; x < 4 && i < delCount; i++ , x++) {
            var newIndex = currentSeed[x] % delCount;
            var b = truncDelegateList[newIndex];
            truncDelegateList[newIndex] = truncDelegateList[i];
            truncDelegateList[i] = b;
        }
        currentSeed = crypto.createHash('sha256').update(currentSeed).digest();
    }
    return truncDelegateList;
}

function generateBlock(height, parentSig, id) {
    const keyPair = keypairStore[id]
    let block = {
        height,
        parentSig,
        minnerId: id,
        minnerPk: keyPair.pk
    }
    let blockStr = JSON.stringify(block)
    let msg = new Uint8Array(Buffer.from(blockStr))
    let sk = new Uint8Array(Buffer.from(keyPair.sk, 'hex'))
    const sig = Buffer.from(nacl.sign.detached(msg, sk)).toString('hex')
    block.sig = sig
    return block
}

init()
addKeypair(ProcessListStore)

async function loop(groupId) {
    if (groupId === 0) {
        const processSort = shuffle('000000', GroupList[0])
        const minner = processSort[0]
        console.log('slot 0 is:', minner)
        let block = generateBlock(blockHeight, '', minner)
        blockHeight++
        let beaconSig = await generateBeaconSig(GroupList[0], k, block.sig)
        block.beaconSig = beaconSig.signature
        console.log(block)
        chain[blockHeight] = block
        const next = bignum(beaconSig.signature).mod(m).toString()
        console.log('Next Group id:', next)
        return loop(parseInt(next))
    } else {
        const processSort = shuffle('000000', GroupList[groupId])
        const minner = processSort[0]
        console.log('slot 0 is:', minner)
        let block = generateBlock(blockHeight, chain[blockHeight - 1].sig, minner)
        blockHeight++
        let beaconSig = await generateBeaconSig(GroupList[0], k, block.sig)
        block.beaconSig = beaconSig.signature
        chain[blockHeight] = block
        console.log(block)
        const next = bignum(beaconSig.signature).mod(m).toString()
        console.log('Next Group id:', next)
        return loop(parseInt(next))
    }
}
loop(0)
