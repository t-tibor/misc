#ifndef __XC_CHECK_OTP__
#define __XC_CHECK_OTP__

#ifdef __cplusplus 
extern "C" {
#endif

// ------------------------------------------------------------------
//                       External dependency
// ------------------------------------------------------------------

	typedef unsigned long OTP_REG_TYPE;
	int OTP_loadRegisterValue(int sensorIdx, char *regName, OTP_REG_TYPE *value);
	void _writeToLog(const char *line);

// ------------------------------------------------------------------
//                         General types
// ------------------------------------------------------------------

	typedef enum { LIMIT_NONE, LIMIT_NORMAL, LIMIT_INVERTED } LimitType_t;
	typedef enum { XC_CHECK_NOK = -1, XC_CHECK_UNKNOWN = 0, XC_CHECK_OK = 1 } XC_CHECK_Result_t;

// ------------------------------------------------------------------
//                    OTP TABLE SPECIFICATION
// ------------------------------------------------------------------

	// register naming format:
	// <BLOCK_PREFIX>_X<addr>
	// if you want to change it, modify the following function:
	int		OTPRegister_parseName(const char* nameIn, const char** pBlockPrefixBuffer, unsigned *regAddr);

	struct OTPBlock;
	struct OTPRegister
	{
		// runtime value
		struct OTPBlock *parent;
		unsigned addr;
		OTP_REG_TYPE value;
		XC_CHECK_Result_t status;		// limit check result
	};

#define OTPBLOCK_MAX_NAME_LENGTH	32
#define OTPREG_MAX_NAME_LENGTH (OTPBLOCK_MAX_NAME_LENGTH + 7)
	struct OTPBlock
	{
		// parsed from XML
		char *blockName;
		unsigned baseAddress;
		unsigned regCnt;

		// run time data
		struct OTPRegister *regs;
	};

	int		OTPBlock_init(struct OTPBlock *block, const char *name, unsigned baseAddress, unsigned regCnt);
	void	OTPBlock_resetRegs(struct OTPBlock *block);
	void	OTPBlock_deinit(struct OTPBlock *block);

#define MAX_OTP_BLOCK_CNT	5
	struct OTPTable
	{
		// parsed from XML
		unsigned reg_width;
		struct OTPBlock blocks[MAX_OTP_BLOCK_CNT];

		// runtime data
		unsigned blockCnt;
	};

	int					OTPTable_init(struct OTPTable *table, unsigned reg_width);
	int					OTPTable_addBlock(struct OTPTable *table, const char*blockName, unsigned baseAddress, unsigned regCnt);
	int					OTPTable_clear(struct OTPTable *table);
	struct OTPRegister*	OTPTable_getRegFromName(struct OTPTable *table, const char*name);
	struct OTPRegister*	OTPTable_getRegFromAddr(struct OTPTable *table, unsigned addr);
	int					OTPTable_getVal(struct OTPTable *table, unsigned addr, OTP_REG_TYPE *value);
	int					OTPTable_printReport(struct OTPTable *table, XC_CHECK_Result_t *result);
	int					OTPTable_deinit(struct OTPTable *table);

// ------------------------------------------------------------------
//                    OTP PARAMETER SPECIFICATION
// ------------------------------------------------------------------

#define OTP_PARAMTER_SIGNED		1
#define OTP_PARAMETER_UNSIGNED	0
	struct OTPParameter
	{
		// parsed from XML
		const char *name;
		unsigned bitCnt;
		unsigned char isSigned;

		// run time data
		unsigned long long rawValue;	// unsigned value used for composing the value from multipe registers
		long long value;				// converted according to signess and bit count
		XC_CHECK_Result_t status;		// limit check result
		struct OTPParameter *pNext;		// for linked list
	};

	struct OTPParameter*	OTPParameter_create(const char *name, unsigned bitCnt, unsigned char isSigned);
	void					OTPParameter_convert(struct OTPParameter *param);
	void					OTPParameter_reset(struct OTPParameter *param);
	int						OTPParameter_printReport(struct OTPParameter *param, XC_CHECK_Result_t *result);

	// OTPParameter linked list operations
	typedef struct OTPParameter* OTPParameterList;
	int						OTPParameterList_addParam(OTPParameterList *pList, struct OTPParameter *param);
	int						OTPParameterList_clear(OTPParameterList *pList);
	struct OTPParameter*	OTPParameterList_getParam(OTPParameterList list, const char *name);

// ------------------------------------------------------------------
//                        PARAMETER MAPPING
// ------------------------------------------------------------------

	struct OTPParameterMapping
	{
		// parsed from xml
		struct OTPRegister *sourceReg;
		OTP_REG_TYPE mask;
		unsigned char sourceBitMin;
		unsigned char sourceBitMax;

		struct OTPParameter *targetParameter;
		unsigned char targetBitMin;
		unsigned char targetBitMax;

		// linked list item
		struct OTPParameterMapping *pNext;
	};

	struct OTPParameterMapping*	OTPParameterMapping_create(struct OTPTable *pTable, OTPParameterList paramList,
									unsigned regAddr, unsigned char sourceBitMin, unsigned char sourceBitMax,
									const char* paramName, unsigned char targetBitMin, unsigned char targetBitMax);
	struct OTPParameterMapping*	OTPParameterMapping_createFromRegName(struct OTPTable *pTable, OTPParameterList paramList,
									const char *regName, unsigned char sourceBitMin, unsigned char sourceBitMax,
									const char* paramName, unsigned char targetBitMin, unsigned char targetBitMax);
	int							OTPParameterMapping_evaluate(struct OTPParameterMapping *mapping);

	// OTPParameterMapping linked list operations
	typedef struct OTPParameterMapping* OTPParameterMappingList;
	int						OTPParameterMappingList_addMapping(OTPParameterMappingList *pList, struct OTPParameterMapping *mapping);
	int						OTPParameterMappingList_clear(OTPParameterMappingList *pList);

	// ------------------------------------------------------------------
	//                             LIMITS
	// ------------------------------------------------------------------

	struct OTPRegisterLimit
	{
		// parsed from limit table
		struct OTPRegister *targetReg;
		OTP_REG_TYPE mask;
		OTP_REG_TYPE targetValue;
		LimitType_t limitType;

		// linked list item
		struct OTPRegisterLimit *pNext;
	};

	struct OTPRegisterLimit*	OTPRegisterLimit_create(struct OTPTable *table, const char* regName, OTP_REG_TYPE mask, OTP_REG_TYPE targetValue, LimitType_t type);
	struct OTPRegisterLimit*	OTPRegisterLimit_createFromLine(struct OTPTable *table, char *line);
	int							OTPRegisterLimit_doLimitCheck(struct OTPRegisterLimit *limit);

	typedef struct OTPRegisterLimit* OTPRegisterLimitList;
	int							OTPRegisterLimitList_addLimit(OTPRegisterLimitList *pList, struct OTPRegisterLimit *limit);
	int							OTPRegisterLimitList_clear(OTPRegisterLimitList *pList);


	struct OTPParameterLimit
	{
		// parsed from limit file
		struct OTPParameter *targetParameter;		
		long lowerLimit;
		long upperLimit;
		LimitType_t limitType;

		// linked list item
		struct OTPParameterLimit *pNext;
	};

	struct OTPParameterLimit*	OTPParameterLimit_create(OTPParameterList params, const char* paramName, long lowerLimit, long upperLimit, LimitType_t type);
	struct OTPParameterLimit*	OTPParameterLimit_createFromLine(OTPParameterList params, char *line);
	int							OTPParameterLimit_doLimitCheck(struct OTPParameterLimit *limit);

	typedef struct OTPParameterLimit* OTPParameterLimitList;
	int							OTPParameterLimitList_addLimit(OTPParameterLimitList *pList, struct OTPParameterLimit *limit);
	int							OTPParameterLimitList_clear(OTPParameterLimitList *pList);

	// ------------------------------------------------------------------
	//                        SENSOR OTP DATA
	// ------------------------------------------------------------------

	struct SensorOTPData
	{
		int sensorIdx; 
		struct OTPTable table;
		OTPParameterList pParamListHead;
		OTPParameterMappingList pMappingListHead;

		struct OTPRegisterLimit *pRegLimitListHead;
		struct OTPParameterLimit *pParamLimitListHead;
	};

	struct SensorOTPData*	SensorOTPData_create();
	int						SensorOTPData_init(struct SensorOTPData *sdata, const char* otp_map_xml_path);
	int						SensorOTPData_addRegisterLimits(struct SensorOTPData *sdata, const char* limit_file_path);
	int						SensorOTPData_addParameterLimits(struct SensorOTPData *sdata, const char* limit_file_path);
	int						SensorOTPData_fillWithSensorData(struct SensorOTPData *sdata, int sensorIdx);
	int						SensorOTPData_evaluate(struct SensorOTPData *sdata, XC_CHECK_Result_t *sensorResult, XC_CHECK_Result_t *otpResult, XC_CHECK_Result_t *paramResult);
	int						SensorOTPData_deinit(struct SensorOTPData *sdata);


	void XC_CHECK_Run_Tests(void);

#ifdef __cplusplus 
}
#endif

#endif