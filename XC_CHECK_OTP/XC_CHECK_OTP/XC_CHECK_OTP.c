#include "pch.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include "XC_CHECK_OTP.h"

#pragma warning(disable : 4996)

#define FOR_EACH_IN_LINKED_LIST(elemType, elemIterator, head, nextField) for(elemType *elemIterator = head; elemIterator != NULL; elemIterator =  elemIterator->nextField)
#define LINKED_LIST_ADD_TO_START(newElem, ptrHead, nextField) {newElem->nextField = *ptrHead; *ptrHead = newElem;}
#define LINKED_LIST_ADD_TO_END(elemType, newElem, ptrHead, nextField) 	{elemType **tmp; \
																		for (tmp = ptrHead; *tmp != NULL; tmp = &(*tmp)->nextField); \
																		*tmp = newElem; \
																		newElem->nextField = NULL;}
#define LINKED_LIST_CLEAR(elemType, ptrHead, nextField)		{elemType *curr = NULL; \
															elemType *next = NULL;	\
															if (!ptrHead) return -1; \
															for (curr = (*ptrHead); curr != NULL; curr = next) \
															{ \
																next = curr->nextField; \
																free(curr); \
															} \
															*ptrHead = NULL;}

// ------------------------------------------------------------------
//                       External dependency
// ------------------------------------------------------------------

// Loads register value from the XC data table 
int OTP_loadRegisterValue(int sensorIdx, char *regName, OTP_REG_TYPE *value)
{
	static int val = 0xAA00;
	*value = ++val;
	return 0;
}

// prints to the log
void _writeToLog(const char *line)
{
	printf("%s\n",line);
}

// ------------------------------------------------------------------
//                             Logging
// ------------------------------------------------------------------
typedef enum
{
	LOG_DEBUG = 0,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR,
	LOG_RAW,		// Writes no prefix to the log	

	LOG_LAST
} logLevel_t;

logLevel_t loglevel = LOG_DEBUG;
const char *loglevelMessages[LOG_LAST] = { "[DEBUG]", "[INFO]" , "[WARNING]" , "[ERROR]" , "" };
static char logLineBuffer[512];
void _log(logLevel_t level, const char *msg, ...)
{
	int writeCnt = 0;
	va_list ap;

	if (level < loglevel) return;

	va_start(ap, msg);
	writeCnt = sprintf(logLineBuffer, "%s", loglevelMessages[level]);
	vsprintf(logLineBuffer + writeCnt, msg, ap);
	_writeToLog(logLineBuffer);
}

// ------------------------------------------------------------------
//                    OTP REGISTER OPERATIONS
// ------------------------------------------------------------------
#define BLOCKNAME_ADDRESS_SEPARATOR			"_X"
#define BLOCKNAME_ADDRESS_SEPARATOR_LEN		2
int OTPRegister_parseName(const char* nameIn, const char** pBlockPrefixBuffer, unsigned *regAddr)
{
	static char pref[OTPBLOCK_MAX_NAME_LENGTH + 2];
	unsigned addr;
	char *separator = NULL;

	memset(pref, 0, OTPBLOCK_MAX_NAME_LENGTH + 2);
	separator = strstr(nameIn, BLOCKNAME_ADDRESS_SEPARATOR);
	if (!separator)	return -1;	
	strncpy(pref, nameIn, separator - nameIn);
	if (sscanf(separator + BLOCKNAME_ADDRESS_SEPARATOR_LEN, "%lx", &addr) == 1)
	{
		pref[OTPBLOCK_MAX_NAME_LENGTH + 1] = 0;
		*pBlockPrefixBuffer = pref;
		*regAddr = addr;
		return 0;
	}
	return -1;
}
#define FOR_EACH_OTP_REG(regIterator, block)		for(struct OTPRegister *regIterator = (block)->regs;  regIterator < (block)->regs + (block)->regCnt; regIterator++)

// ------------------------------------------------------------------
//                    OTP REGISTER BLOCK OPERATIONS
// ------------------------------------------------------------------

#define FOR_EACH_OTP_BLOCK(blkIterator, table)		for(struct OTPBlock *blkIterator = (table)->blocks;   blkIterator < (table)->blocks + (table)->blockCnt; blkIterator++)

void OTPBlock_deinit(struct OTPBlock *block)
{
	if (block->blockName != NULL)
	{
		free(block->blockName);
		block->blockName = NULL;
	}
	block->baseAddress = 0;
	block->regCnt = 0;
	if (block->regs != NULL)
	{
		free(block->regs);
		block->regs = NULL;
	}
}

int OTPBlock_init(struct OTPBlock *block, const char *name, unsigned baseAddress, unsigned regCnt)
{
	OTPBlock_deinit(block);
	block->blockName = strdup(name);
	if (block->blockName == NULL) return -1;
	block->baseAddress = baseAddress;
	block->regCnt = regCnt;
	block->regs = calloc(regCnt, sizeof(struct OTPRegister));
	if (block->regs == NULL)
	{
		OTPBlock_deinit(block);
		return -1;
	}
	OTPBlock_resetRegs(block);

	return 0;
}

void OTPBlock_resetRegs(struct OTPBlock *block)
{
	for (unsigned regIdx = 0; regIdx < block->regCnt; regIdx++)
	{
		block->regs[regIdx].parent = block;
		block->regs[regIdx].value = 0;
		block->regs[regIdx].addr = block->baseAddress + regIdx;
		block->regs[regIdx].status = XC_CHECK_UNKNOWN;
	}
}

// ------------------------------------------------------------------
//                    OTP TABLE OPERATIONS
// ------------------------------------------------------------------

int	OTPTable_deinit(struct OTPTable *pTable)
{
	if (!pTable) return -1;

	pTable->reg_width = 0;
	pTable->blockCnt = 0;
	// reset all block descriptors
	for (int blockIdx = 0; blockIdx < MAX_OTP_BLOCK_CNT; blockIdx++)
	{
		OTPBlock_deinit(&(pTable->blocks[blockIdx]));
	}

	return 0;
}

int	OTPTable_init(struct OTPTable *pTable, unsigned reg_width)
{
	if (!pTable) return -1;

	OTPTable_deinit(pTable);
	pTable->reg_width = reg_width;
	return 0;
}

int OTPTable_addBlock(struct OTPTable *pTable, const char*blockName, unsigned baseAddress, unsigned regCnt)
{
	int retVal = 0;

	if (pTable == NULL) return -1;
	if (blockName == NULL) return -2;
	if (pTable->blockCnt >= MAX_OTP_BLOCK_CNT)
	{
		_log(LOG_ERROR, "Cannot add new register block (%s): maximum allowed block count reached.", blockName);
		return -3;
	}
	if (strlen(blockName) > OTPBLOCK_MAX_NAME_LENGTH)
	{
		_log(LOG_ERROR, "Cannot add new register block (%s): block name is too long.", blockName);
		return -4;
	}
	retVal = OTPBlock_init(&(pTable->blocks[pTable->blockCnt]), blockName, baseAddress, regCnt);
	if (retVal == 0)
	{
		pTable->blockCnt++;
	}
	return retVal;
}

int	OTPTable_clear(struct OTPTable *pTable)
{
	if (!pTable) return -1;

	for (unsigned blockIdx = 0; blockIdx < pTable->blockCnt; blockIdx++)
	{
		OTPBlock_resetRegs(&(pTable->blocks[blockIdx]));
	}
	return 0;
}

struct OTPRegister*	OTPTable_getRegFromName(struct OTPTable *pTable, const char*name)
{
	const char *blockName = NULL;
	unsigned addr = 0;
	struct OTPRegister *retVal = NULL;

	if (pTable == NULL) return NULL;
	if (name == NULL) return NULL;
	if (OTPRegister_parseName(name, &blockName, &addr)) return NULL;
	
	for (unsigned blockIdx = 0; (blockIdx < pTable->blockCnt) && (!retVal); blockIdx++)
	{
		struct OTPBlock *blk = &pTable->blocks[blockIdx];
		// check against block name
		if (!strncmp(blk->blockName, blockName, OTPBLOCK_MAX_NAME_LENGTH + 1))
		{
			// check against address
			unsigned startAddr = blk->baseAddress;
			unsigned endAddr = startAddr + blk->regCnt - 1;

			if ((addr >= startAddr) && (addr <= endAddr))
			{
				unsigned offset = addr - startAddr;
				retVal = &(blk->regs[offset]);
			}
		}		
	}
	return retVal;
}

struct OTPRegister*	OTPTable_getRegFromAddr(struct OTPTable *pTable, unsigned addr)
{
	struct OTPRegister *retVal = NULL;

	for (unsigned blockIdx = 0; (blockIdx < pTable->blockCnt) && (!retVal); blockIdx++)
	{
		struct OTPBlock *blk = &pTable->blocks[blockIdx];
		unsigned startAddr = blk->baseAddress;
		unsigned endAddr = startAddr + blk->regCnt - 1;

		if ((addr >= startAddr) && (addr <= endAddr))
		{
			unsigned offset = addr - startAddr;
			retVal = &(blk->regs[offset]);
		}
	}
	return retVal;
}

int OTPTable_getVal(struct OTPTable *pTable, unsigned addr, OTP_REG_TYPE *pValue)
{
	struct OTPRegister *reg = NULL;

	if (!pTable) return -1;
	reg = OTPTable_getRegFromAddr(pTable, addr);
	if (!reg) return -2;

	*pValue = reg->value;
	return 0;
}

int	OTPTable_printReport(struct OTPTable *table, XC_CHECK_Result_t *result)
{
	XC_CHECK_Result_t summaryState= XC_CHECK_OK;

	if (!table) return -1;

	FOR_EACH_OTP_BLOCK(blk, table)
	{
		_log(LOG_RAW, "\tOTP block: %s", blk->blockName);
		FOR_EACH_OTP_REG(reg, blk)
		{
			if (reg->status == XC_CHECK_UNKNOWN)
			{
				_log(LOG_RAW, "\t\t0x%x\t-\t%5x", reg->addr, reg->value);
			}
			else if (reg->status == XC_CHECK_OK)
			{
				_log(LOG_RAW, "\t\t0x%x\t-\t%5x\t->\tok", reg->addr, reg->value);
			}
			else if(reg->status == XC_CHECK_NOK)
			{
				summaryState = XC_CHECK_NOK;
				_log(LOG_RAW, "\t\t0x%x\t-\t%5x\t->\t[---NOK---]", reg->addr, reg->value);
			}
			else assert(0);
		}
	}

	if (result != NULL) *result = summaryState;
	return 0;
}

// ------------------------------------------------------------------
//                    OTP PARAMETER OPERATIONS
// ------------------------------------------------------------------

struct OTPParameter* OTPParameter_create(const char *name, unsigned bitCnt, unsigned char isSigned)
{
	struct OTPParameter *retVal = NULL;

	if (name == NULL) return NULL;
	retVal = (struct OTPParameter*)malloc(sizeof(struct OTPParameter));
	if (!retVal) return NULL;
	memset(retVal, 0, sizeof(struct OTPParameter));
	retVal->bitCnt = bitCnt;
	retVal->isSigned = isSigned;
	retVal->name = strdup(name);
	if (retVal->name == NULL)
	{
		free(retVal);
		return NULL;
	}
	retVal->status = XC_CHECK_UNKNOWN;

	return retVal;
}

void OTPParameter_convert(struct OTPParameter *param)
{
	param->value = param->rawValue;
	if (param->isSigned != 0)
	{	
		if (param->value >= (1LL << ((long long)(param->bitCnt - 1))))
		{
			param->value -= (1LL << (long long)(param->bitCnt));
		}
	}
}

void OTPParameter_reset(struct OTPParameter *param)
{
	param->rawValue = 0;
	param->value = 0;
	param->status = XC_CHECK_UNKNOWN;
}

int OTPParameter_printReport(struct OTPParameter * param, XC_CHECK_Result_t * result)
{
	if (param->status == XC_CHECK_UNKNOWN)
	{
		_log(LOG_RAW, "\t%20s\t-\t%lld", param->name, param->value);
	}
	else if (param->status == XC_CHECK_OK)
	{
		_log(LOG_RAW, "\t%20s\t-\t%lld\t->\tok", param->name, param->value);
	}
	else if (param->status = XC_CHECK_NOK)
	{
		_log(LOG_RAW, "\t%20s\t-\t%lld\t->\t[---NOK---]", param->name, param->value);
	}
	else assert(0);

	if (result) *result = param->status;
	return 0;
}

// ------------------ OTP PARAMETER LIST OPERATIONS ------------------

#define FOR_EACH_PARAMETER(paramIterator, paramList) FOR_EACH_IN_LINKED_LIST(struct OTPParameter, paramIterator, paramList, pNext)

int OTPParameterList_addParam(OTPParameterList *pList, struct OTPParameter *param)
{
	if (!pList) return -1;
	if (!param) return -2;
	LINKED_LIST_ADD_TO_END(struct OTPParameter, param, pList, pNext)
	return 0;
}

int OTPParameterList_clear(OTPParameterList *pList)
{
	if (!pList) return -1;
	LINKED_LIST_CLEAR(struct OTPParameter, pList, pNext)
	return 0;
}

struct OTPParameter* OTPParameterList_getParam(OTPParameterList list, const char *name)
{
	struct OTPParameter *retVal = NULL;

	if (list == NULL) return NULL;
	if (name == NULL) return NULL;

	FOR_EACH_PARAMETER(param, list)
	{
		if (!strcmp(param->name, name))
		{
			retVal = param;
			break;
		}
	}
	return retVal;
}

// ------------------------------------------------------------------
//                    OTP PARAMETER MAPPING OPERATIONS
// ------------------------------------------------------------------

struct OTPParameterMapping* _otp_parameter_mapping_create(struct OTPTable *pTable,
	struct OTPRegister *sreg, unsigned char sourceBitMin, unsigned char sourceBitMax,
	struct OTPParameter *param, unsigned char targetBitMin, unsigned char targetBitMax)
{
	struct OTPParameterMapping *retVal = NULL;

	// validate input data
	if (sourceBitMax < sourceBitMin)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping between reg 0x%x and param %s: invalid source bit indices.", sreg->addr, param->name);
		return NULL;
	}
	if (targetBitMax < targetBitMin)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping between reg 0x%x and param %s: invalid target bit indices.", sreg->addr, param->name);
		return NULL;
	}
	if (sourceBitMax >= pTable->reg_width)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping between reg 0x%x and param %s: reading bits over register width.", sreg->addr, param->name);
		return NULL;
	}
	if (targetBitMax >= param->bitCnt)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping between reg 0x%x and param %s: writing bits over parameter width.", sreg->addr, param->name);
		return NULL;
	}
	if (sourceBitMax - sourceBitMin != targetBitMax - targetBitMin)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping between reg 0x%x and param %s: source and target slice has different length.", sreg->addr, param->name);
		return NULL;
	}

	// if ok, then create the mapping
	retVal = (struct OTPParameterMapping*)malloc(sizeof(struct OTPParameterMapping));
	if (!retVal) return NULL;
	memset(retVal, 0, sizeof(struct OTPParameterMapping));
	retVal->mask = -1;
	retVal->sourceBitMax = sourceBitMax;
	retVal->sourceBitMin = sourceBitMin;
	retVal->sourceReg = sreg;
	retVal->targetBitMax = targetBitMax;
	retVal->sourceBitMin = targetBitMin;
	retVal->targetParameter = param;
	retVal->pNext = NULL;
	return retVal;
}

struct OTPParameterMapping* OTPParameterMapping_create(struct OTPTable *pTable, OTPParameterList paramList,
	unsigned regAddr, unsigned char sourceBitMin, unsigned char sourceBitMax,
	const char* paramName, unsigned char targetBitMin, unsigned char targetBitMax)
{
	struct OTPParameterMapping *retVal = NULL;
	struct OTPRegister *sreg = NULL;
	struct OTPParameter *param = NULL;

	if (!pTable) return NULL;
	if (!paramName) return NULL;

	// locate source register and target parameter descriptor
	sreg = OTPTable_getRegFromAddr(pTable, regAddr);
	if (!sreg)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping: register with address 0x%x does not exist in the OTP table.", regAddr);
		return NULL;
	}
	param = OTPParameterList_getParam(paramList, paramName);
	if (!param)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping: parameter with name %s does not exist.", paramName);
		return NULL;
	}
	return _otp_parameter_mapping_create(pTable, sreg, sourceBitMin, sourceBitMax, param, targetBitMin, targetBitMax);
}

struct OTPParameterMapping* OTPParameterMapping_createFromRegName(struct OTPTable *pTable, OTPParameterList paramList,
	const char *regName, unsigned char sourceBitMin, unsigned char sourceBitMax,
	const char* paramName, unsigned char targetBitMin, unsigned char targetBitMax)
{
	struct OTPParameterMapping *retVal = NULL;
	struct OTPRegister *sreg = NULL;
	struct OTPParameter *param = NULL;

	if (!pTable) return NULL;
	if (!paramName) return NULL;

	// locate source register and target parameter descriptor
	sreg = OTPTable_getRegFromName(pTable, regName);
	if (!sreg)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping: register with name %s does not exist in the OTP table.", regName);
		return NULL;
	}
	param = OTPParameterList_getParam(paramList, paramName);
	if (!param)
	{
		_log(LOG_ERROR, "Cannot create parameter mapping: parameter with name %s does not exist.", paramName);
		return NULL;
	}
	return _otp_parameter_mapping_create(pTable, sreg, sourceBitMin, sourceBitMax, param, targetBitMin, targetBitMax);
}

int OTPParameterMapping_evaluate(struct OTPParameterMapping *mapping)
{
	// do all the processing on 64 bits
	unsigned long long value;
	unsigned bitCnt;
	unsigned shift;

	if (!mapping) return -1;

	// cutting out the relevant source region
	value = mapping->sourceReg->value;
	shift = mapping->sourceBitMin;
	bitCnt = mapping->sourceBitMax - mapping->sourceBitMin + 1;
	value >>= shift;
	value &= ((1ULL << bitCnt) - 1);

	// paste it to the target value
	bitCnt = mapping->targetBitMax - mapping->targetBitMin + 1;
	shift = mapping->targetBitMin;
	value &= ((1ULL << bitCnt) - 1);
	value <<= shift;
	mapping->targetParameter->rawValue |= value;
	return 0;	
}

// ------------------ OTP PARAMETER MAPPING LIST OPERATIONS ------------------

#define FOR_EACH_MAPPING(mapIterator, mapList) FOR_EACH_IN_LINKED_LIST(struct OTPParameterMapping, mapIterator, mapList, pNext)

int OTPParameterMappingList_addMapping(OTPParameterMappingList *pList, struct OTPParameterMapping *mapping)
{
	if (!pList) return -1;
	if (!mapping) return -2;
	LINKED_LIST_ADD_TO_START(mapping,pList, pNext)
	return 0;
}

int OTPParameterMappingList_clear(OTPParameterMappingList *pList)
{
	if (!pList) return -1;
	LINKED_LIST_CLEAR(struct OTPParameterMapping, pList, pNext)
	return 0;
}

// ------------------------------------------------------------------
//                    OTP REGISTER LIMIT OPERATIONS
// ------------------------------------------------------------------

struct OTPRegisterLimit* OTPRegisterLimit_create(struct OTPTable *table, const char* regName, OTP_REG_TYPE mask, OTP_REG_TYPE targetValue, LimitType_t type)
{
	struct OTPRegisterLimit *retVal = NULL;
	struct OTPRegister *target = NULL;

	if (table == NULL) return NULL;
	if (regName == NULL) return NULL;

	target = OTPTable_getRegFromName(table, regName);
	if (!target) return NULL;

	retVal = (struct OTPRegisterLimit*)calloc(1, sizeof(struct OTPRegisterLimit));
	if (!retVal) return NULL;
	retVal->targetReg = target;
	retVal->mask = mask;
	retVal->targetValue = targetValue;
	retVal->limitType = type;
	retVal->pNext = NULL;
	return retVal;
}

// Replaces the whitespaces on the end of the string, and skips the initial whitespaces with the returned pointer
char *_strip(char *str)
{
	char *start = str;
	char *end = str + strlen(str) - 1;

	// skipping initial spaces
	while ((*start == ' ') || (*start == '\t')) start++;
	// skipping end spaces
	while ((end > start) && ((*end == ' ') || (*end == '\t') || (*end == '\n') || (*end == '\r'))) *end-- = 0;

	return start;
}

int _scan_number(char *str, unsigned long *result)
{
	int ret = 0;
	if ((strncmp(str, "0x", 2) == 0) || (strncmp(str, "0X", 2) == 0))
	{
		ret = sscanf(str + 2, "%lx", result);
	}
	else
	{
		ret = sscanf(str, "%lu", result);
	}
	if (ret != 1) return -1;
	return 0;
}
// Register limit format:
// <register name>; <mask>; <target value>; <limit type>
struct OTPRegisterLimit *OTPRegisterLimit_createFromLine(struct OTPTable *table, char *line)
{
	char *sRegName = NULL;
	char *sMask = NULL;
	char *sTargetValue = NULL;
	char *sLimitType = NULL;

	unsigned long mask;
	unsigned long targetValue;
	LimitType_t limitType;

	if (!table) return NULL;
	if (!line) return NULL;

	sRegName = strtok(line, ";,"); sMask = strtok(NULL, ";,"); sTargetValue = strtok(NULL, ";,"); sLimitType = strtok(NULL, ";,");
	if (!sRegName || !sMask || !sTargetValue || !sLimitType)
	{
		_log(LOG_ERROR, "Error during register limit parsing: missing values in the line: %s", line);
		return NULL;
	}
	sRegName = _strip(sRegName); sMask = _strip(sMask); sTargetValue = _strip(sTargetValue); sLimitType = _strip(sLimitType);
	if (_scan_number(sMask, &mask))
	{
		_log(LOG_ERROR, "Error during register limit parsing: invalid mask string: %s", sMask);
		return NULL;
	}
	if (_scan_number(sTargetValue, &targetValue))
	{
		_log(LOG_ERROR, "Error during register limit parsing: invalid target value string: %s", sTargetValue);
		return NULL;
	}
	if (!strcmp(sLimitType, "NORMAL") || !strcmp(sLimitType, "NORM"))
	{
		limitType = LIMIT_NORMAL;
	}
	else if (!strcmp(sLimitType, "INVERTED") || !strcmp(sLimitType, "INV"))
	{
		limitType = LIMIT_INVERTED;
	}
	else
	{
		_log(LOG_ERROR, "Error during register limit parsing: invalid limit type string: %s", sLimitType);
		return NULL;
	}

	return OTPRegisterLimit_create(table, sRegName, (OTP_REG_TYPE)mask, (OTP_REG_TYPE)targetValue, limitType);
}

int OTPRegisterLimit_doLimitCheck(struct OTPRegisterLimit *limit)
{
	XC_CHECK_Result_t result = XC_CHECK_UNKNOWN;
	struct OTPRegister *reg = NULL;
	OTP_REG_TYPE valueMasked, targetMasked;

	if (limit == NULL) return -1;

	reg = limit->targetReg;
	if (reg == NULL) return -2;

	valueMasked = reg->value & limit->mask;
	targetMasked = limit->targetValue & limit->mask;

	if (limit->limitType == LIMIT_NORMAL)
	{
		if (valueMasked == targetMasked)
		{
			result = XC_CHECK_OK;
			_log(LOG_RAW, "%s_X%x\tvalue:0x%x\tmask:0x%x\tmasked:0x%x\tshould:    0x%x --> ok", reg->parent->blockName, reg->addr, reg->value, limit->mask, valueMasked, targetMasked);
		}
		else
		{
			result = XC_CHECK_NOK;
			_log(LOG_RAW, "%s_X%x\tvalue:0x%x\tmask:0x%x\tmasked:0x%x\tshould:    0x%x --> [---NOK---]", reg->parent->blockName, reg->addr, reg->value, limit->mask,valueMasked, targetMasked);
		}
	}
	else if (limit->limitType == LIMIT_INVERTED)
	{
		if (valueMasked == targetMasked)
		{
			result = XC_CHECK_NOK;
			_log(LOG_RAW, "%s_X%x\tvalue:0x%x\tmask:0x%x\tmasked:0x%x\tsould not: 0x%x --> [---NOK---]", reg->parent->blockName, reg->addr, reg->value, limit->mask, valueMasked, targetMasked);
		}
		else
		{
			result = XC_CHECK_OK;
			_log(LOG_RAW, "%s_X%x\tvalue:0x%x\tmask:0x%x\tmasked:0x%x\tsould not: 0x%x --> ok", reg->parent->blockName, reg->addr, reg->value, limit->mask, valueMasked, targetMasked);
		}
	}
	else assert(0);

	if ((reg->status == XC_CHECK_UNKNOWN) || (reg->status == XC_CHECK_OK))
	{
		reg->status = result;
	}

	return 0;
}

// ------------------ OTP REGISTER LIMIT LIST OPERATIONS ------------------

#define FOR_EACH_REGISTER_LIMIT(limitIterator, list) FOR_EACH_IN_LINKED_LIST(struct OTPRegisterLimit, limitIterator, list, pNext)

int OTPRegisterLimitList_addLimit(OTPRegisterLimitList *pList, struct OTPRegisterLimit *limit)
{
	if (!pList) return -1;
	if (!limit) return -2;
	LINKED_LIST_ADD_TO_END(struct OTPRegisterLimit, limit, pList, pNext)
	return 0;
}

int OTPRegisterLimitList_clear(OTPRegisterLimitList *pList)
{
	if (!pList) return -1;
	LINKED_LIST_CLEAR(struct OTPRegisterLimit, pList, pNext)
	return 0;
}

// ------------------------------------------------------------------
//                    OTP PARAMETER LIMIT OPERATIONS
// ------------------------------------------------------------------

struct OTPParameterLimit* OTPParameterLimit_create(OTPParameterList params, const char* paramName, long lowerLimit, long upperLimit, LimitType_t type)
{
	struct OTPParameter *target = NULL;
	struct OTPParameterLimit *retVal = NULL;

	if (params == NULL) return NULL;
	if (paramName == NULL) return NULL;

	target = OTPParameterList_getParam(params, paramName);
	if (!target)
	{
		_log(LOG_ERROR, "No parameter found with name: %s", paramName);
		return NULL;
	}

	retVal = (struct OTPParameterLimit *)calloc(1, sizeof(struct OTPParameterLimit));
	if (!retVal) return NULL;

	retVal->targetParameter = target;
	retVal->lowerLimit = lowerLimit;
	retVal->upperLimit = upperLimit;
	retVal->limitType = type;
	retVal->pNext = NULL;

	return retVal;
}

struct OTPParameterLimit* OTPParameterLimit_createFromLine(OTPParameterList params, char *line)
{
	char *sParamName = NULL;
	char *sLowerLimit = NULL;
	char *sUpperLimit = NULL;
	char *sLimitType = NULL;

	long lowerLimit = 0;
	long upperLimit = 0;
	LimitType_t limitType;

	if (!params) return NULL;
	if (!line) return NULL;

	sParamName = strtok(line, ";,"); sLowerLimit = strtok(NULL, ";,"); sUpperLimit = strtok(NULL, ";,"); sLimitType = strtok(NULL, ";,");
	if (!sParamName || !sLowerLimit || !sUpperLimit || !sLimitType)
	{
		_log(LOG_ERROR, "Error during register limit parsing: missing values in the line: %s", line);
		return NULL;
	}
	sParamName = _strip(sParamName); sLowerLimit = _strip(sLowerLimit); sUpperLimit = _strip(sUpperLimit); sLimitType = _strip(sLimitType);
	if (sscanf(sLowerLimit,"%ld",&lowerLimit) != 1)
	{
		_log(LOG_ERROR, "Error during parameter limit parsing: invalid lower limit  string: %s", sLowerLimit);
		return NULL;
	}
	if (sscanf(sUpperLimit, "%ld", &upperLimit) != 1)
	{
		_log(LOG_ERROR, "Error during parameter limit parsing: invalid upper limit  string: %s", sUpperLimit);
		return NULL;
	}
	if (!strcmp(sLimitType, "NORMAL") || !strcmp(sLimitType, "NORM"))
	{
		limitType = LIMIT_NORMAL;
	}
	else if (!strcmp(sLimitType, "INVERTED") || !strcmp(sLimitType, "INV"))
	{
		limitType = LIMIT_INVERTED;
	}
	else
	{
		_log(LOG_ERROR, "Error during register limit parsing: invalid limit type string: %s", sLimitType);
		return NULL;
	}

	return OTPParameterLimit_create(params, sParamName, lowerLimit, upperLimit, limitType);
}

int OTPParameterLimit_doLimitCheck(struct OTPParameterLimit *limit)
{
	XC_CHECK_Result_t result = XC_CHECK_UNKNOWN;
	struct OTPParameter *param = NULL;

	if (limit == NULL) return -1;

	param = limit->targetParameter;
	if (param == NULL) return -2;

	if (limit->limitType == LIMIT_NORMAL)
	{
		if ((limit->lowerLimit <= param->value) && (param->value <= limit->upperLimit))
		{
			result = XC_CHECK_OK;
			_log(LOG_RAW, "Name:%s\t%ld<=\tvalue=%lld\t<=%d  --> ok", param->name, limit->lowerLimit, param->value, limit->upperLimit);
		}
		else
		{
			result = XC_CHECK_NOK;
			_log(LOG_RAW, "Name:%s\t%ld<=\tvalue=%lld\t<=%d --> [---NOK---]", param->name, limit->lowerLimit, param->value, limit->upperLimit);
		}
	}
	else if (limit->limitType == LIMIT_INVERTED)
	{
		if ((limit->lowerLimit <= param->value) && (param->value <= limit->upperLimit))
		{
			result = XC_CHECK_NOK;
			_log(LOG_RAW, "Name:%s\tvalue=%lld < %ld or \t%ld < value=%lld --> [---NOK---]", param->name, param->value, limit->lowerLimit, limit->upperLimit, param->value);
		}
		else
		{
			result = XC_CHECK_OK;
			_log(LOG_RAW, "Name:%s\tvalue=%lld < %ld or \t%ld < value=%lld --> ok", param->name, param->value, limit->lowerLimit, limit->upperLimit, param->value);
		}
	}
	else assert(0);

	if ((param->status == XC_CHECK_UNKNOWN) || (param->status == XC_CHECK_OK))
	{
		param->status = result;
	}

	return 0;
}

// ------------------ OTP PARAMETER LIMIT LIST OPERATIONS ------------------

#define FOR_EACH_PARAMETER_LIMIT(limitIterator, list) FOR_EACH_IN_LINKED_LIST(struct OTPParameterLimit, limitIterator, list, pNext)

int OTPParameterLimitList_addLimit(OTPParameterLimitList *pList, struct OTPParameterLimit *limit)
{
	if (!pList) return -1;
	if (!limit) return -2;
	LINKED_LIST_ADD_TO_END(struct OTPParameterLimit, limit, pList, pNext)
	return 0;
}

int OTPParameterLimitList_clear(OTPParameterLimitList *pList)
{
	if (!pList) return -1;
	LINKED_LIST_CLEAR(struct OTPParameterLimit, pList, pNext)
	return 0;
}


// ------------------------------------------------------------------
//                        SENSOR OTP DATA
// ------------------------------------------------------------------
struct SensorOTPData *SensorOTPData_create()
{
	return (struct SensorOTPData*)calloc(1, sizeof(struct SensorOTPData));
}

int SensorOTPData_init(struct SensorOTPData *sdata, const char* otp_map_xml_path)
{
	int err;

	if (!sdata) return -1;
	SensorOTPData_deinit(sdata);

	// todo XML parsing
	OTPTable_init(&sdata->table, 16);


	// add register blocks
	err = OTPTable_addBlock(&sdata->table, "SMP_REG", 0x70, 10);
	if (err)
	{
		_log(LOG_ERROR, "Cannot add register block.");
	}
	err = OTPTable_addBlock(&sdata->table, "PPS_REG", 0x100, 20);
	if (err)
	{
		_log(LOG_ERROR, "Cannot add register block.");
		
	}

	// add parameters
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("CLIN0", 16, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("CLIN1", 16, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("CLIN2", 16, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("CLIN3", 16, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("TCO0", 8, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("TCO1", 8, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("TCO2", 8, 1));
	OTPParameterList_addParam(&sdata->pParamListHead, OTPParameter_create("TCO3", 8, 0));

	// add mapping
	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"SMP_REG_X70", 0, 15, "CLIN0", 0, 15));
	
	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"SMP_REG_X71", 0, 15, "CLIN1", 0, 15));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"SMP_REG_X72", 0, 15, "CLIN2", 0, 15));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"SMP_REG_X73", 0, 15, "CLIN3", 0, 15));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"PPS_REG_X100", 0, 7, "TCO0", 0, 7));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"PPS_REG_X101", 8, 15, "TCO1", 0, 7));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_createFromRegName(&sdata->table, sdata->pParamListHead,
			"PPS_REG_X102", 0, 7, "TCO2", 0, 7));

	OTPParameterMappingList_addMapping(&sdata->pMappingListHead,
		OTPParameterMapping_create(&sdata->table, sdata->pParamListHead,
			0x103, 8, 15, "TCO3", 0, 7));

	// reset all register values
	OTPTable_clear(&sdata->table);

	return 0;
}

#define LINE_BUFFER_SIZE 256
char *_parse_file(FILE *f, int *lineIdx)
{
	int lineLen = 0;
	char *start, *commentPos;
	char *retVal = NULL;
	static char line[LINE_BUFFER_SIZE];

	while(fgets(line, LINE_BUFFER_SIZE, f))
	{
		(*lineIdx)++;
		lineLen = strlen(line);
		if (lineLen == LINE_BUFFER_SIZE - 1)
		{
			_log(LOG_ERROR, "Register limit file contains too long line at line idx: %d. Max line length can be: %d.", lineIdx, LINE_BUFFER_SIZE);
			return NULL;
		}
		// skip commented section
		commentPos = strchr(line, '#');
		if (commentPos != NULL)
		{
			*commentPos = '\0';
		}
		// skip initial and ending white space
		start = _strip(line);
		if (strlen(start) > 1)
		{
			return start;
		}
	}
	return NULL;
}
int SensorOTPData_addRegisterLimits(struct SensorOTPData *sdata, const char* limit_file_path)
{
	FILE *f = NULL;
	int lineIdx = 0;
	struct OTPRegisterLimit *limit = NULL;
	int newLimitCnt = 0;

	if (!sdata) return -1;
	if (!limit_file_path) return -2;

	f = fopen(limit_file_path, "r");
	if (!f)
	{
		_log(LOG_ERROR, "Cannot open register limit file with path: %s", limit_file_path);
		return -1;
	}
	for(char *line = _parse_file(f, &lineIdx); line != NULL; line = _parse_file(f, &lineIdx))
	{
		limit = OTPRegisterLimit_createFromLine(&sdata->table, line);
		if (!limit)
		{
			_log(LOG_ERROR, "Cannot create register limit from line %d: %s", lineIdx, line);
			fclose(f);
			return -4;
		}
		if (OTPRegisterLimitList_addLimit(&sdata->pRegLimitListHead, limit))
		{
			_log(LOG_ERROR, "Cannot add register limit to the limit list.");
			fclose(f);
			return -5;
		}
		newLimitCnt++;
	}
	fclose(f);
	_log(LOG_INFO, "Loaded %d register limits.", newLimitCnt);
	return 0;
}

int SensorOTPData_addParameterLimits(struct SensorOTPData *sdata, const char* limit_file_path)
{
	FILE *f = NULL;
	int lineIdx = 0;
	struct OTPParameterLimit *limit = NULL;
	int newLimitCnt = 0;

	if (!sdata) return -1;
	if (!limit_file_path) return -2;

	f = fopen(limit_file_path, "r");
	if (!f)
	{
		_log(LOG_ERROR, "Cannot open parameter limit file with path: %s", limit_file_path);
		return -1;
	}

	for (char *line = _parse_file(f, &lineIdx); line != NULL; line = _parse_file(f, &lineIdx))
	{
		limit = OTPParameterLimit_createFromLine(sdata->pParamListHead, line);
		if (!limit)
		{
			_log(LOG_ERROR, "Cannot create parameter limit from line %d: %s", lineIdx, line);
			fclose(f);
			return -4;
		}

		if (OTPParameterLimitList_addLimit(&sdata->pParamLimitListHead, limit))
		{
			_log(LOG_ERROR, "Cannot add register limit to the limit list.");
			fclose(f);
			return -5;
		}
		newLimitCnt++;
	}
	fclose(f);
	_log(LOG_INFO, "Loaded %d parameter limits.", newLimitCnt);
	return 0;
}

int SensorOTPData_fillWithSensorData(struct SensorOTPData *sdata, int sensorIdx)
{
	char regName[OTPREG_MAX_NAME_LENGTH];
	OTP_REG_TYPE regValue;

	if (!sdata) return -1;

	// reset the register / parameter values
	OTPTable_clear(&sdata->table);
	FOR_EACH_PARAMETER(param, sdata->pParamListHead)
	{
		OTPParameter_reset(param);
	}
	sdata->sensorIdx = sensorIdx;

	// read up the new register values
	FOR_EACH_OTP_BLOCK(blk,&sdata->table)
	{
		FOR_EACH_OTP_REG(reg,blk)
		{
			sprintf(regName, "%s_X%x", blk->blockName, reg->addr);
			if (!OTP_loadRegisterValue(sensorIdx, regName, &regValue))
			{
				reg->value = regValue;
			}
			else
			{
				_log(LOG_ERROR, "Cannot load register value for %s. Terminating...", regName);
				return -1;
			}
		}
	}
	_log(LOG_INFO, "Sensor %d OTP table loaded.", sensorIdx);
	return 0;
}

int SensorOTPData_evaluate(struct SensorOTPData *sdata, XC_CHECK_Result_t *sensorResult, XC_CHECK_Result_t *otpResult, XC_CHECK_Result_t *paramResult)
{
	XC_CHECK_Result_t sres = XC_CHECK_OK;
	XC_CHECK_Result_t ores = XC_CHECK_OK;
	XC_CHECK_Result_t pres = XC_CHECK_OK;

	if (!sdata) return -1;
	_log(LOG_INFO, "Processing OTP data from sensor %d.", sdata->sensorIdx);

	_log(LOG_DEBUG, "Calculating otp parameter values.");
	FOR_EACH_MAPPING(map, sdata->pMappingListHead)
		OTPParameterMapping_evaluate(map);

	_log(LOG_DEBUG, "Converting otp parameter values.");
	FOR_EACH_PARAMETER(param, sdata->pParamListHead)
		OTPParameter_convert(param);

	_log(LOG_DEBUG, "Checking OTP register limits.");
	FOR_EACH_REGISTER_LIMIT(regLimit, sdata->pRegLimitListHead)
		OTPRegisterLimit_doLimitCheck(regLimit);

	_log(LOG_DEBUG, "Checking OTP parameter limits.");
	FOR_EACH_PARAMETER_LIMIT(paramLimit, sdata->pParamLimitListHead)
		OTPParameterLimit_doLimitCheck(paramLimit);

	_log(LOG_RAW, "OTP DUMP:");
	OTPTable_printReport(&sdata->table, &ores);

	_log(LOG_RAW, "PARAMETER DUMP:");
	FOR_EACH_PARAMETER(param, sdata->pParamListHead)
	{
		XC_CHECK_Result_t tmp = XC_CHECK_UNKNOWN;
		OTPParameter_printReport(param, &tmp);
		if (tmp == XC_CHECK_NOK) pres = XC_CHECK_NOK;
	}

	if ((ores == XC_CHECK_NOK) || (pres == XC_CHECK_NOK)) sres = XC_CHECK_NOK;
	if (sensorResult) *sensorResult = sres;
	if (otpResult) *otpResult = ores;
	if (paramResult) *paramResult = pres;
	return 0;
}

int SensorOTPData_deinit(struct SensorOTPData *sdata)
{
	if (!sdata) return -1;
	OTPTable_deinit(&sdata->table);
	OTPParameterList_clear(&sdata->pParamListHead);
	OTPParameterMappingList_clear(&sdata->pMappingListHead);
	OTPRegisterLimitList_clear(&sdata->pRegLimitListHead);
	OTPParameterLimitList_clear(&sdata->pParamLimitListHead);
	return 0;
}


// Unit tests
const char *testName;
int okCnt, badCnt;
void TestStart(const char *t) { testName = (t); okCnt = badCnt = 0; }
void TestOK(void) { okCnt++; }
void TestNOK(void) { badCnt++; }
void TestEnd(void)
{
	fprintf(stderr, "Test: %s finished. Passed: %d, Failed: %d\n", testName, okCnt, badCnt);
}

#define EVAL(exp, failMsg,...) {if((exp)) {TestOK();} else {TestNOK(); fprintf(stderr,"\t");fprintf(stderr,failMsg,__VA_ARGS__);}}
#define TEXIFY_(x) #x
#define TEXIFY(x) TEXIFY_(x)
#define ASSERT_TRUE(x)			EVAL(x, "Assertion FAILED: expression %s it not true. Line:%d\n",#x, __LINE__)
#define ASSERT_EQ(v1,v2)		EVAL((v1) == (v2), "Assertion FAILED: values are not equal. Line:%d\n")
#define ASSERT_NOT_EQ(v1,v2)	EVAL((v1) != (v2),  "Assertion FAILED: values are not equal. Line:%d", __LINE__)
#define ASSERT_STR_EQ(s1,s2)	EVAL(!strcmp((s1),(s2)), "Assertion FAILED: strings are not equal: %s != %s. Line:%d",s1,s2, __LINE__)
void Test0(void)
{
	TestStart("parseName test");
	int ret;
	const char *blk;
	unsigned addr;
	ret = OTPRegister_parseName("REG_X66", &blk, &addr);
	ASSERT_EQ(ret, 0);
	ASSERT_STR_EQ(blk, "REG");
	ASSERT_EQ(addr, 0x68);

	ret = OTPRegister_parseName("_X66", &blk, &addr);
	ASSERT_EQ(ret, 0);
	ASSERT_STR_EQ(blk, "");
	ASSERT_EQ(addr, 0x66);

	ret = OTPRegister_parseName("REG_66", &blk, &addr);
	ASSERT_NOT_EQ(ret, 0);

	TestEnd();
}
void Test1(void)
{
	printf("\n\n--------------------------\nTEST1\n----------------------\n");
	int err = 0;
	XC_CHECK_Result_t res;
	struct SensorOTPData *sdata = SensorOTPData_create();

	SensorOTPData_init(sdata, "");
	SensorOTPData_fillWithSensorData(sdata, 1);
	SensorOTPData_evaluate(sdata, &res, NULL, NULL);
	SensorOTPData_deinit(sdata);
}

void Test2(void)
{
	printf("\n\n--------------------------\nTEST2\n----------------------\n");
	int err = 0;
	XC_CHECK_Result_t res;
	struct SensorOTPData *sdata = SensorOTPData_create();

	SensorOTPData_init(sdata, "");
	SensorOTPData_addRegisterLimits(sdata, "registerLimits.txt");
	SensorOTPData_addParameterLimits(sdata, "parameterLimits.txt");

	SensorOTPData_fillWithSensorData(sdata, 1);
	SensorOTPData_evaluate(sdata, &res, NULL, NULL);

	SensorOTPData_fillWithSensorData(sdata, 2);
	SensorOTPData_evaluate(sdata, &res, NULL, NULL);
	if (res == XC_CHECK_NOK) printf("Sensor %d failed.\n", sdata->sensorIdx);

	SensorOTPData_deinit(sdata);
}

typedef void(*testFunc_t)(void);
void XC_CHECK_Run_Tests(void)
{
	testFunc_t tests[] = { Test0, Test1, Test2};

	for (int i = 0; i < sizeof(tests)/sizeof(tests[0]); i++)
	{
		tests[i]();
	}
}
