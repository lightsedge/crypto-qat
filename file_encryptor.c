
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"
#include "rt_utils.h"

/********************************************************************************/

extern int gDebugParam = 0;

/********************************************************************************/


#define TIMEOUT_MS  5000    // 5 seconds
#define MAX_PATH    1024
// Function qatMemAllocNUMA can only allocate a contiguous memory with size up
// to 1MB, otherwise return error.
#define MAX_HW_BUFSZ    1*1024*1024 // 1 MB
#define AES_BLOCKSZ     32          // 32 Bytes (256 bits)
// The following definition refers to /etc/dh895xcc_dev0.conf: SSL:
#define MAX_INSTANCES   8
#define MAX_THREADS     MAX_INSTANCES

typedef struct {
    int isEnc;
    int nrThread;
    char fileToEncrypt[MAX_PATH];
    char fileToWrite[MAX_PATH];
} CmdlineArgs;

typedef struct {
    char *src, *dst;
    unsigned int totalBytes;
    int isEnc;
    int threadId;
    int nrThread;
} WorkerArgs;

typedef struct {
    pthread_mutex_t mutex;
    int isInit;
    int idx;
    Cpa16U nrCyInstHandles;
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
} QatHardware;

typedef struct {
    CpaInstanceHandle cyInstHandle;
    CpaCySymSessionCtx ctx;
} QatAes256EcbSession;

typedef struct RunTime_ {
    struct timeval timeS;
    struct timeval timeE;
    struct RunTime_ *next;
} RunTime;

static QatHardware gQatHardware = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .isInit = 0,
    .nrCyInstHandles = 0,
    .idx = 0};
static CmdlineArgs gCmdlineArgs = {
    .isEnc = 1,
    .nrThread = 1};

// 256 bits-long
static Cpa8U sampleCipherKey[] = {
//    0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,};

static RunTime *gRunTimeHead = NULL;
static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;


/********************************************************************************/


/* Source data to encrypt */
static Cpa8U sampleCipherSrc[] = {
    0xD7, 0x1B, 0xA4, 0xCA, 0xEC, 0xBD, 0x15, 0xE2, 0x52, 0x6A, 0x21, 0x0B,
    0x81, 0x77, 0x0C, 0x90, 0x68, 0xF6, 0x86, 0x50, 0xC6, 0x2C, 0x6E, 0xED,
    0x2F, 0x68, 0x39, 0x71, 0x75, 0x1D, 0x94, 0xF9, 0x0B, 0x21, 0x39, 0x06,
    0xBE, 0x20, 0x94, 0xC3, 0x43, 0x4F, 0x92, 0xC9, 0x07, 0xAA, 0xFE, 0x7F,
    0xCF, 0x05, 0x28, 0x6B, 0x82, 0xC4, 0xD7, 0x5E, 0xF3, 0xC7, 0x74, 0x68,
    0xCF, 0x05, 0x28, 0x6B, 0x82, 0xC4, 0xD7, 0x5E, 0xF3, 0xC7, 0x74, 0x68,
    0x80, 0x8B, 0x28, 0x8D, 0xCD, 0xCA, 0x94, 0xB8, 0xF5, 0x66, 0x0C, 0x00,
    0x5C, 0x69, 0xFC, 0xE8, 0x7F, 0x0D, 0x81, 0x97, 0x48, 0xC3, 0x6D, 0x24};


/* Initialization vector */
static Cpa8U sampleCipherIv[] =
    {0x7E, 0x9B, 0x4C, 0x1D, 0x82, 0x4A, 0xC5, 0xDF};


/* Expected output of the encryption operation with the specified
 * cipher (CPA_CY_SYM_CIPHER_3DES_CBC), key (sampleCipherKey) and
 * initialization vector (sampleCipherIv) */
static Cpa8U expectedOutput[] = {
    0x35, 0x0C, 0x46, 0xF8, 0xFE, 0x13, 0x8A, 0x7C, 0x9B, 0x66, 0x83, 0x5F,
    0x94, 0xDC, 0x4F, 0x96, 0x66, 0x56, 0x35, 0xC3, 0xFA, 0xFD, 0x51, 0xA1,
    0xC9, 0x3B, 0xAF, 0x06, 0x2A, 0xA9, 0x54, 0x0D, 0xF1, 0x0B, 0xBB, 0xB1,
    0x27, 0x15, 0x9D, 0xD2, 0x08, 0xAC, 0xF0, 0x92, 0x47, 0x19, 0xE2, 0xC1,
    0x47, 0xAC, 0x34, 0x30, 0x8C, 0x95, 0x1B, 0x14, 0xD4, 0x71, 0x37, 0x4B,
    0x50, 0xCB, 0x73, 0xAA, 0x4F, 0x98, 0x36, 0xF1, 0x97, 0xE2, 0x8C, 0x37,
    0x6C, 0x44, 0xC2, 0xFD, 0xAD, 0xE4, 0xF5, 0x56, 0x62, 0x92, 0xEF, 0x84,
    0x9E, 0x33, 0x0D, 0x5B, 0x34, 0x27, 0xA0, 0x2B, 0x9B, 0x7C, 0xE7, 0x8A,
};

/********************************************************************************/


void runTimePush(RunTime *pNode)
{
    pthread_mutex_lock(&gMutex);
    pNode->next = gRunTimeHead;
    gRunTimeHead = pNode;
    pthread_mutex_unlock(&gMutex);
}

void showStats(RunTime *pHead, unsigned int totalBytes)
{
    unsigned long usBegin = 0;
    unsigned long usEnd   = 0;
    double usDiff         = 0;

    for (RunTime *pCurr = pHead; pCurr != NULL; pCurr = pCurr->next) {
        usBegin = pCurr->timeS.tv_sec * 1e6 + pCurr->timeS.tv_sec;
        usEnd   = pCurr->timeE.tv_sec * 1e6 + pCurr->timeE.tv_sec;
        usDiff  += (usEnd - usBegin);
    }

    if (usDiff == 0 || totalBytes == 0) {
        RT_PRINT("Too fast to calculate throughput. Try larger workload or refine this counter.\n")
        return;
    }

    double throughput = ((double)totalBytes * 8) / usDiff;

    RT_PRINT("Time taken:     %9.3lf ms\n", usDiff / 1000);
    RT_PRINT("Throughput:     %9.3lf Mbit/s\n", throughput);
}

// Callback function
//
// This function is "called back" (invoked by the implementation of
// the API) when the asynchronous operation has completed.  The
// context in which it is invoked depends on the implementation, but
// as described in the API it should not sleep (since it may be called
// in a context which does not permit sleeping, e.g. a Linux bottom
// half).
//
// This function can perform whatever processing is appropriate to the
// application.  For example, it may free memory, continue processing
// of a decrypted packet, etc.  In this example, the function only
// sets the complete variable to indicate it has been called.
static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    RT_PRINT_DBG("Callback called with status = %d.\n", status);
    COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
}

static CpaStatus cipherPerformOp(CpaInstanceHandle cyInstHandle,
                                 CpaCySymSessionCtx sessionCtx,
                                 char *src, unsigned int srcLen,
                                 char *dst, unsigned int dstLen)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;

    // TODO #2: This function performs a cipher operation and is critical to encryption's
    // performance. Please implement it as efficient as possible. Your can refer
    // to ./cpa_cipher_sample.c.

/********************************************************************************/

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = sizeof(sampleCipherSrc);
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;

    PRINT_DBG("cpaCyBufferListGetMetaSize\n");

    /*
     * Different implementations of the API require different
     * amounts of space to store meta-data associated with buffer
     * lists.  We query the API to find out how much space the current
     * implementation needs, and then allocate space for the buffer
     * meta data, the buffer list, and for the buffer itself.  We also
     * allocate memory for the initialization vector.  We then
     * populate this memory with the required data.
     */
    //<snippet name="memAlloc">
    status =
        cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMeta, bufferMetaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferList, bufferListMemSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pIvBuffer, sizeof(sampleCipherIv));
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, sampleCipherSrc, sizeof(sampleCipherSrc));

        /* copy IV into buffer */
        memcpy(pIvBuffer, sampleCipherIv, sizeof(sampleCipherIv));

        /* increment by sizeof(CpaBufferList) to get at the
         * array of flatbuffers */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);

        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = 1;
        pBufferList->pPrivateMetaData = pBufferMeta;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Populate the structure containing the operational data needed
         * to run the algorithm:
         * - packet type information (the algorithm can operate on a full
         *   packet, perform a partial operation and maintain the state or
         *   complete the last part of a multi-part operation)
         * - the initialization vector and its length
         * - the offset in the source buffer
         * - the length of the source message
         */
        //<snippet name="opData">
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->pIv = pIvBuffer;
        pOpData->ivLenInBytes = sizeof(sampleCipherIv);
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = sizeof(sampleCipherSrc);
        //</snippet>
    }

    /*
     * Now, we initialize the completion variable which is used by the callback
     * function
     * to indicate that the operation is complete.  We then perform the
     * operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCySymPerformOp\n");

        //<snippet name="perfOp">
        COMPLETION_INIT(&complete);

        status = cpaCySymPerformOp(
            cyInstHandle,
            (void *)&complete, /* data sent as is to the callback function*/
            pOpData,           /* operational data struct */
            pBufferList,       /* source buffer list */
            pBufferList,       /* same src & dst for an in-place operation*/
            NULL);
        //</snippet>

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp failed. (status = %d)\n", status);
        }

        /*
         * We now wait until the completion of the operation.  This uses a macro
         * which can be defined differently for different OSes.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            //<snippet name="completion">
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaCySymPerformOp\n");
                status = CPA_STATUS_FAIL;
            }
            //</snippet>
        }

        /*
         * We now check that the output matches the expected output.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (0 == memcmp(pSrcBuffer, expectedOutput, bufferSize))
            {
                PRINT_DBG("Output matches expected output\n");
            }
            else
            {
                PRINT_DBG("Output does not match expected output\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pIvBuffer);
    OS_FREE(pBufferList);
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

/********************************************************************************/    

    return rc;
}

// It's thread-safety.
CpaStatus qatAes256EcbSessionInit(QatAes256EcbSession *sess, int isEnc)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionSetupData sessionSetupData = {0};

    // \begin acquire a CY instance
    pthread_mutex_lock(&gQatHardware.mutex);
    if (gQatHardware.isInit == -1) {
        rc = CPA_STATUS_FAIL;
        goto unlock;
    } else if (!gQatHardware.isInit) {
        // Find out all available CY instances at first time
        if (CPA_STATUS_SUCCESS != cpaCyGetNumInstances(&gQatHardware.nrCyInstHandles) ||
                gQatHardware.nrCyInstHandles == 0) {
            RT_PRINT_ERR("No instances found for 'SSL'\n");
            rc = CPA_STATUS_FAIL;
            gQatHardware.isInit = -1;
            goto unlock;
        } {
            RT_PRINT("%d instances found\n", gQatHardware.nrCyInstHandles);
        }
        if (CPA_STATUS_SUCCESS != cpaCyGetInstances(gQatHardware.nrCyInstHandles,
                                        gQatHardware.cyInstHandles)) {
            RT_PRINT_ERR("Failed to initialize instances.\n");
            rc = CPA_STATUS_FAIL;
            gQatHardware.isInit = -1;
            goto unlock;
        } {
            gQatHardware.isInit = 1;
        }
    }
    // FIXME: ensure that gQatHardware.idx < gQatHardware.nrCyInstHandles
    sess->cyInstHandle = gQatHardware.cyInstHandles[gQatHardware.idx++];
unlock:
    pthread_mutex_unlock(&gQatHardware.mutex);
    CHECK(rc);
    // \end acquire a CY instance

    // \begin setup a QAT_AES-256-ECB session
    CHECK(cpaCyStartInstance(sess->cyInstHandle));
    CHECK(cpaCySetAddressTranslation(sess->cyInstHandle, sampleVirtToPhys));

    sampleCyStartPolling(sess->cyInstHandle);

    // We now populate the fields of the session operational data and create
    // the session.  Note that the size required to store a session is
    // implementation-dependent, so we query the API first to determine how
    // much memory to allocate, and then allocate that memory.
    //
    // Populate the session setup structure for the operation required
    // TODO #1: please fillup the following properties in sessionSetupData
    // for AES-256-ECB encrypt/decrypt operation:
    sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;   //Normal priority
    sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;    //Cipher only operation on the data
    sessionSetupData.cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_ECB;    //本次实验使用 AES-256-ECB 加密算法
    sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;   //密钥, 已经在前面定义了
    sessionSetupData.cipherSetupData.cipherKeyLenInBytes = sizeof(sampleCipherKey);     //密钥长度
    sessionSetupData.cipherSetupData.cipherDirection =
        isEnc ? CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT : CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
    RT_PRINT_DBG("@sessionSetupData.cipherSetupData.cipherKeyLenInBytes = %ld\n", sizeof(sampleCipherKey));

    // Determine size of session context to allocate
    CHECK(cpaCySymSessionCtxGetSize(sess->cyInstHandle, &sessionSetupData,
                &sessionCtxSize));
    // Allocate session context
    CHECK(PHYS_CONTIG_ALLOC(&sess->ctx, sessionCtxSize));
    // Initialize the Cipher session
    CHECK(cpaCySymInitSession(sess->cyInstHandle,
                              symCallback,       // callback function
                              &sessionSetupData, // session setup data
                              sess->ctx));       // output of the function
    // \end setup a QAT_AES-256-ECB session

    return rc;
}

void qatAes256EcbSessionFree(QatAes256EcbSession *sess)
{
    cpaCySymRemoveSession(sess->cyInstHandle, sess->ctx);
    PHYS_CONTIG_FREE(sess->ctx);
    sampleCyStopPolling();
    cpaCyStopInstance(sess->cyInstHandle);
}

CpaStatus qatAes256EcbEnc(char *src, unsigned int srcLen, char *dst,
        unsigned int dstLen, int isEnc)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    QatAes256EcbSession *sess = calloc(1, sizeof(QatAes256EcbSession));
    CpaCySymStats64 symStats = {0};

    // Acquire a QAT_CY instance & initialize a QAT_CY_SYM_AES_256_ECB session
    qatAes256EcbSessionInit(sess, isEnc);

    // Perform Cipher operation (sync / async / batch, etc.)
    rc = cipherPerformOp(sess->cyInstHandle, sess->ctx, src, srcLen, dst, dstLen);

    // Wait for inflight requests before free resources
    symSessionWaitForInflightReq(sess->ctx);

    // Print statistics in this session
    CHECK(cpaCySymQueryStats64(sess->cyInstHandle, &symStats));
    RT_PRINT("Number of symmetic operation completed: %llu\n",
            (unsigned long long)symStats.numSymOpCompleted);

    qatAes256EcbSessionFree(sess);

    return rc;
}

// Thread entrypoint.
void *workerThreadStart(void *threadArgs)
{
    WorkerArgs *args = (WorkerArgs *)threadArgs;

    unsigned int totalBlocks = args->totalBytes / AES_BLOCKSZ;
    // Just check if args->totalBytes is legal: aligned to AES_BLOCKSZ
    unsigned int remainingBytes = args->totalBytes % AES_BLOCKSZ;
    assert(remainingBytes == 0);
    unsigned int strideInBlock = totalBlocks / args->nrThread;
    unsigned int remainingBlocks = totalBlocks % args->nrThread;
    unsigned int offInBytes = strideInBlock * args->threadId * AES_BLOCKSZ;

    // Assign remaining blocks to last worker
    if (remainingBlocks > 0 && args->threadId == (args->nrThread-1))
        strideInBlock += remainingBlocks;

    char *src = args->src + offInBytes;
    unsigned int srcLen = strideInBlock * AES_BLOCKSZ;
    char *dst = args->dst + offInBytes;
    unsigned int dstLen = srcLen;

    CHECK(qatAes256EcbEnc(src, srcLen, dst, dstLen, args->isEnc));

    return NULL;
}

unsigned int fileSize(int fd)
{
    struct stat statbuf;
    OS_CHECK(fstat(fd, &statbuf));
    return (unsigned int)statbuf.st_size;
}

void doEncryptFile(CmdlineArgs *cmdlineArgs)
{
    int fd0 = open(cmdlineArgs->fileToEncrypt, O_RDONLY);
    OS_CHECK(fd0);
    int fd1 = open(cmdlineArgs->fileToWrite, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    OS_CHECK(fd1);

    unsigned int totalInBytes = fileSize(fd0);
    assert(totalInBytes > 0);
    // Aligned to AES_BLOCKSZ
    unsigned int r = totalInBytes % AES_BLOCKSZ;
    unsigned int totalOutBytes = (r == 0) ?
        totalInBytes : (totalInBytes - r + AES_BLOCKSZ);
    assert(totalInBytes <= totalOutBytes);

    // Use mmap to convert file-style read/write to memory-style read/write
    char *src = (char *)mmap(NULL, totalInBytes, PROT_READ, MAP_PRIVATE, fd0, 0);
    assert(src != NULL);
    // Use anonymous mmaped memory here to avoid pre-allocating fileToWrite
    char *dst = (char *)mmap(NULL, totalOutBytes, PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    assert(dst != NULL);

    // Since mmap always align size of mmapped memory to PAGE_SIZE (4KB in common)
    // and AES_BLOCKSZ is a factor of PAGE_SIZE, so aligned totalInBytes
    // (i.e. totalOutBytes) is less than size of mmapped memory. And, access to
    // region execeding size of mmaped file will get zero that is exactly we want
    // in doing encryption with AES. So we can safely use src/dst as input/output
    // buffer and totalOutBytes as buffer's length. See blow figure:
    //
    // Address space of the mmaped fileToEncrypt that is aligned to PAGE_SIZE:
    // ------------------------------------------------------------------------
    //     ...    | AES_BLOCK | AES_BLOCK |    ...    | AES_BLOCK |  PADDING  |
    // ------------------------------------------------------------------------
    // ----------------totalInBytes (not aligned)------->|
    // ---------------totalOutBytes (aligned to AES_BLOCK)------->|

    // Prepare thread arguments
    pthread_t workers[MAX_THREADS];
    WorkerArgs args[MAX_THREADS];
    for (int i = 0; i < cmdlineArgs->nrThread; i++) {
        args[i].src = src;
        args[i].dst = dst;
        args[i].totalBytes = totalOutBytes;
        args[i].isEnc = cmdlineArgs->isEnc;
        args[i].nrThread = cmdlineArgs->nrThread;
        args[i].threadId = i;
    }
    
    // \begin timer
    RunTime *rt = (RunTime *)calloc(1, sizeof(RunTime));
    gettimeofday(&rt->timeS, NULL);

    // Fire up all threads. Note that nrThread-1 pthreads are created and the
    // main thread is used as a worker as well
    for (int i = 1; i < cmdlineArgs->nrThread; i++)
        pthread_create(&workers[i], NULL, workerThreadStart, &args[i]);

    workerThreadStart((void *)&args[0]);

    // Wait for worker threads to complete
    for (int i = 1; i < cmdlineArgs->nrThread; i++)
        pthread_join(workers[i], NULL);

    gettimeofday(&rt->timeE, NULL);
    runTimePush(rt);
    // \end timer

    // Show throughput
    showStats(gRunTimeHead, totalInBytes);

    // Print the first AES_BLOCK
    RT_PRINT_DBG("1st AES_BLOCK @src_buffer: %.*s\n", AES_BLOCKSZ, src);
    RT_PRINT_DBG("1st AES_BLOCK @dst_buffer: %.*s\n", AES_BLOCKSZ, dst);

    // Flush data in dst_buffer into fileToWrite
    ssize_t bytesWritten = write(fd1, dst, totalOutBytes);
    assert(bytesWritten == totalOutBytes);

    OS_CHECK(munmap(src, totalInBytes));
    OS_CHECK(munmap(dst, totalOutBytes));
    OS_CHECK(close(fd0));
    OS_CHECK(close(fd1));
}

void printUsage(const char *progname)
{
    printf("Usage: %s [options] <file_to_enc>\n", progname);
    printf("Program options:\n");
    printf("    -t  --thread <INT>          Number of thread to co-operate the given file\n");
    printf("    -w  --file_to_write <PATH>  File to save output data\n");
    printf("    -d  --decrypt               Switch to decryption mode\n");
    printf("    -h  --help                  This message\n");
}

// About code style: since QAT APIs use camel case, we begin to follow it.
int main(int argc, char *argv[])
{
    // \begin parse commandline args
    int opt;

    static struct option longOptions[] = {
        {"thread",        required_argument, 0, 't'},
        {"file_to_write", required_argument, 0, 'w'},
        {"decrypt",       no_argument,       0, 'd'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "t:w:dh", longOptions, NULL)) != -1) {
        switch (opt) {
            case 't':
                gCmdlineArgs.nrThread = atoi(optarg);
                assert(gCmdlineArgs.nrThread > 0 && gCmdlineArgs.nrThread <= MAX_THREADS);
                break;
            case 'w':
                sprintf(gCmdlineArgs.fileToWrite, "%s", optarg);
                break;
            case 'd':
                gCmdlineArgs.isEnc = 0;
                break;
            case 'h':
            case '?':
            default:
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        sprintf(gCmdlineArgs.fileToEncrypt, "%s", argv[optind++]);
    } else {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    // Construct fileToWrite
    if (strlen(gCmdlineArgs.fileToWrite) == 0) {
        char *suffix = gCmdlineArgs.isEnc ? "enc" : "dec";
        sprintf(gCmdlineArgs.fileToWrite, "%s.%s", gCmdlineArgs.fileToEncrypt, suffix);
    }
    // \end parse commandline args

    // CHECK(expr) := assert(CPA_STATUS_SUCCESS == (expr)). If assertion fails,
    // it will print error code/string, then exit. Your will find macro
    // CHECK(expr) useful when locating bug. So wrap some critical funtion
    // as far as possible. However, you can write your own error handler.
    CHECK(qaeMemInit());
    CHECK(icp_sal_userStartMultiProcess("SSL", CPA_FALSE));

    // Enter main function
    doEncryptFile(&gCmdlineArgs);

    icp_sal_userStop();
    qaeMemDestroy();

    return 0;
}
