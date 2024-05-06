CREATE OR REPLACE PACKAGE "MSA_SCHEMA".pkg_auth IS
  -- Function to authenticate users and return a token
  FUNCTION login(USERNAME IN VARCHAR2, PASSWORD IN VARCHAR2) RETURN VARCHAR2;

  -- Procedure to validate a token
  PROCEDURE validate_token(token IN VARCHAR2, is_valid OUT BOOLEAN);

  -- Function to generate OTP for a given operator
  FUNCTION generate_otp(MOBILE IN VARCHAR2, NATIONAL IN VARCHAR2) RETURN VARCHAR2;

  -- Procedure to validate OTP
  PROCEDURE validate_otp(USER_ID IN NUMBER,
                         OTPS         IN VARCHAR2,
                         is_valid    OUT BOOLEAN);
END pkg_auth;


CREATE OR REPLACE PACKAGE BODY "MSA_SCHEMA".pkg_auth IS
FUNCTION LOGIN(USERNAME IN VARCHAR2, PASSWORD IN VARCHAR2) RETURN VARCHAR2 IS
    TYPE user_record_type IS RECORD (
    l_user_id MSA_SCHEMA.OPERATORS.ID%TYPE,
    l_id MSA_SCHEMA.PROVIDERS.ID%TYPE,
    l_firstname MSA_SCHEMA.PROVIDERS.FIRSTNAME%TYPE,
    l_lastname MSA_SCHEMA.PROVIDERS.LASTNAME%TYPE,
    l_isactive MSA_SCHEMA.PROVIDERS.ISACTIVE%TYPE
  );
    L_PRIVATE_KEY RAW(1000) := UTL_RAW.CAST_TO_RAW('django-insecure-9-#j9$8rh_9k$aq6@#6+k8u@r1x4r#87ne5v^s^cf86fiykrm4'); -- Your private key for signing the token
    l_user_record user_record_type;
    L_HEADER VARCHAR2(1000) := '{"alg": "HS256","typ": "JWT"}';
    L_USER_ID NUMBER;
    L_FIRSTNAME VARCHAR2(50);
    L_LASTNAME VARCHAR2(50);
    L_ID NUMBER;
    L_ISACTIVE CHAR(1);
    L_EXPIRATION_DATE TIMESTAMP;
    L_TOKEN_PAYLOAD VARCHAR2(32767); -- Modified to hold a larger string
    L_SIGNATURE RAW(32767);
    FINAL_SIGNATURE VARCHAR2(32767); -- Modified to hold a larger string
    FINAL_SIGNATURE1 VARCHAR2(32767);
    L_TOKEN VARCHAR2(32767); -- Modified to hold a larger string
    LVAR_USERNAME VARCHAR2(256) := USERNAME;
    LVAR_PASSWORD VARCHAR2(256) := PASSWORD;
    LCURRENT_DATE DATE := TRUNC(SYSDATE); -- To get the current date without time
    L_EXISTING_TOKEN number(10);
    EXISTING_TOKEN VARCHAR2(32767); -- To hold the existing token
BEGIN
SELECT count(*) INTO L_EXISTING_TOKEN
    FROM MSA_SCHEMA.AUTHENTICATION
   WHERE OPERATORID = (SELECT ID
                         FROM MSA_SCHEMA.operators
                        WHERE USERNAME = LVAR_USERNAME
                          AND PASSWORD = LVAR_PASSWORD
                          AND ISACTIVE = 1)
     AND TRUNC(CREATIONDATE) = LCURRENT_DATE;

  IF L_EXISTING_TOKEN > 0 THEN
    SELECT TOKEN INTO EXISTING_TOKEN
    FROM MSA_SCHEMA.AUTHENTICATION
   WHERE OPERATORID = (SELECT ID
                         FROM MSA_SCHEMA.operators
                        WHERE USERNAME = LVAR_USERNAME
                          AND PASSWORD = LVAR_PASSWORD
                          AND ISACTIVE = 1)
     AND TRUNC(CREATIONDATE) = LCURRENT_DATE;
    RETURN EXISTING_TOKEN;
  END IF;
    -- Check username and password against the operators table
  SELECT T.ID, P.ID, P.FIRSTNAME, P.LASTNAME, P.ISACTIVE
  INTO l_user_record
  FROM MSA_SCHEMA.OPERATORS T
  INNER JOIN MSA_SCHEMA.PROVIDERS P ON T.PROVIDER = P.ID
  WHERE T.USERNAME = LVAR_USERNAME
  AND T.PASSWORD = LVAR_PASSWORD
  AND T.ISACTIVE = 1;
  L_USER_ID := l_user_record.l_user_id;
  L_ID := l_user_record.l_id;
  L_FIRSTNAME := l_user_record.l_firstname;
  L_LASTNAME := l_user_record.l_lastname;
  L_ISACTIVE := l_user_record.l_isactive;    

    -- Set the expiration date for the token (1 day from current time)
    L_EXPIRATION_DATE := SYSTIMESTAMP + INTERVAL '1' DAY;

    -- Construct the token payload string
    L_TOKEN_PAYLOAD := '{"sub": "' || LVAR_USERNAME || '", "user_id": ' || L_USER_ID || ', "exp": ' || 'TO_CHAR(EXTRACT(EPOCH FROM ' || L_EXPIRATION_DATE || '))}';

    -- Create the header and payload
    L_TOKEN := UTL_RAW.CAST_TO_VARCHAR2(UTL_RAW.CONCAT(UTL_RAW.CAST_TO_RAW(L_HEADER), UTL_RAW.CAST_TO_RAW('.'), UTL_RAW.CAST_TO_RAW(L_TOKEN_PAYLOAD)));

    -- Create the signature
    SELECT DBMS_CRYPTO.HASH(
               UTL_RAW.CAST_TO_RAW(L_TOKEN),
               DBMS_CRYPTO.HASH_SH256
           ) INTO L_SIGNATURE FROM DUAL;

    -- Base64 encode the signature
    L_SIGNATURE := UTL_ENCODE.BASE64_ENCODE(L_SIGNATURE);

    -- Append the signature to the token
    --L_TOKEN := L_TOKEN || '.' || UTL_RAW.CAST_TO_VARCHAR2(L_SIGNATURE);
    FINAL_SIGNATURE1 := UTL_RAW.CAST_TO_VARCHAR2(L_SIGNATURE);
    FINAL_SIGNATURE := 'jwttoken:'||FINAL_SIGNATURE1||'-*-ID:'||L_ID||'-*-FIRSTNAME:'||L_FIRSTNAME||'-*-LASTNAME:'||L_LASTNAME||'-*-ISACTIVE:'||L_ISACTIVE;
    -- INSERT TOKEN INTO AUTHENTICATION TABLE WITH EXPIRY DATE
    INSERT INTO MSA_SCHEMA.AUTHENTICATION
      (OPERATORID, TOKEN, CREATIONDATE, EXPIRYDATE, STATUS)
    VALUES
      (L_USER_ID,
       FINAL_SIGNATURE1,
       SYSTIMESTAMP,
       L_EXPIRATION_DATE,
       1);

    -- Commit the transaction
    COMMIT;

    RETURN FINAL_SIGNATURE;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RETURN NULL;
END LOGIN;

  PROCEDURE VALIDATE_TOKEN(TOKEN IN VARCHAR2, IS_VALID OUT BOOLEAN) IS
    TOKEN_EXPIRY DATE;
    LVR_TOKEN VARCHAR2(256) := TOKEN;
  BEGIN
    SELECT EXPIRYDATE
      INTO TOKEN_EXPIRY
      FROM MSA_SCHEMA.AUTHENTICATION
     WHERE TOKEN = LVR_TOKEN
       AND STATUS = 1;
    IS_VALID := TRUNC(TOKEN_EXPIRY) > TRUNC(SYSDATE);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      IS_VALID := FALSE;
  END VALIDATE_TOKEN;

  FUNCTION GENERATE_OTP(MOBILE IN VARCHAR2, NATIONAL IN VARCHAR2) RETURN VARCHAR2 IS
    NEW_OTP VARCHAR2(8);
    NEW_OTP1 VARCHAR2(4);
    L_CHANNELTYPE NUMBER(10) := 2;
    ALL_RETURN VARCHAR2(32767);
    L_NATIONALCODE NUMBER(10);
  BEGIN 
  SELECT COUNT(*) INTO L_NATIONALCODE
  FROM MSA_SCHEMA.TBL_OTP
  WHERE MOBILENUMBER = MOBILE
  AND NATIONALCODE = NATIONAL;
  
  NEW_OTP := TRUNC(DBMS_RANDOM.VALUE(10000000, 99999999));
  NEW_OTP1 := TRUNC(DBMS_RANDOM.VALUE(1000, 9999));
  
  IF L_NATIONALCODE >0  THEN
    -- Update the existing record
    UPDATE MSA_SCHEMA.TBL_OTP
    SET OTP_MAIN = NEW_OTP,
        OTP_SECOND = NEW_OTP1,
        EXPIREDATE = SYSDATE
    WHERE MOBILENUMBER = MOBILE
    AND NATIONALCODE = NATIONAL;
    COMMIT;
  ELSE
    -- Insert a new record
    INSERT INTO MSA_SCHEMA.TBL_OTP (MOBILENUMBER, NATIONALCODE, EXPIREDATE , CHANNELTYPE, OTP_MAIN, OTP_SECOND)
    VALUES (MOBILE, NATIONAL, SYSDATE, L_CHANNELTYPE ,NEW_OTP, NEW_OTP1);
    COMMIT;
  END IF;
    -- GENERATE OTP LOGIC (PSEUDO-CODE, USE YOUR METHOD FOR OTP GENERATION)
    /*NEW_OTP := TRUNC(DBMS_RANDOM.VALUE(10000000, 99999999));
    NEW_OTP1 := TRUNC(DBMS_RANDOM.VALUE(1000, 9999));*/
    -- UPDATE OR INSERT OTP INTO A DEDICATED OTP TABLE OR FIELD
    /*INSERT INTO MSA_SCHEMA.TBL_OTP VALUES();    
    COMMIT;
    SELECT CHANNELTYPE INTO L_CHANNELTYPE FROM MSA_SCHEMA.OPERATORS WHERE ID = OPERATOR_ID;*/
    
    ALL_RETURN := 'otpmain:'||NEW_OTP||'-*-otpsecond:'|| NEW_OTP1 ||'-*-L_CHANNELTYPE:'||L_CHANNELTYPE;
    RETURN ALL_RETURN;
  END GENERATE_OTP;

  PROCEDURE VALIDATE_OTP(USER_ID IN NUMBER,
                         OTPS         IN VARCHAR2,
                         IS_VALID    OUT BOOLEAN) IS
    CURRENT_OTP VARCHAR2(8);
    EXPIRATION_DATE DATE;
    L_OTPS VARCHAR2(8) := OTPS;
    L_TIME_DIFFERENCE NUMBER;
  BEGIN
    
SELECT OTP_MAIN, EXPIREDATE
      INTO CURRENT_OTP, EXPIRATION_DATE
      FROM MSA_SCHEMA.TBL_OTP
     WHERE ID = USER_ID;
     
      SELECT (SYSDATE - EXPIRATION_DATE) * 24 * 60
  INTO L_TIME_DIFFERENCE
  FROM dual;

    IS_VALID := (CURRENT_OTP = L_OTPS) AND (L_TIME_DIFFERENCE <= 5 );
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      IS_VALID := FALSE;
  END VALIDATE_OTP;

END pkg_auth;


CREATE OR REPLACE PACKAGE "MSA_SCHEMA".PKG_ORDER AS
    PROCEDURE ESTELAM(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE PROCESS_JSON_DATA(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE CONFIRM_ORDER(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE REVERSE_ORDER_DISTRIBUTION(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
END PKG_ORDER;


CREATE OR REPLACE PACKAGE BODY "MSA_SCHEMA".PKG_ORDER AS

    PROCEDURE  ESTELAM(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2) IS
        -- Declare variables
        V_RRN VARCHAR2(50);
        V_STAN VARCHAR2(50);
        V_NATIONAL_CODE VARCHAR2(100);
        V_CARD_NUMBER VARCHAR2(50);
        V_TERMINAL_NUMBER VARCHAR2(50);
        V_CHANNEL_TYPE NUMBER;
        V_REQUEST_DATE DATE;
        V_AMOUNT NUMBER;
        V2_AMOUNT NUMBER;
        V_COMMODITY_CODE VARCHAR2(50);
        V_QUANTITY NUMBER;
        V_UNIT_CODE VARCHAR2(10);
        V_UNIT_CODE_INT VARCHAR2(10);
        V_ORDER_ID NUMBER;
        JSON_DATA JSON_OBJECT_T;
        ORDER_ITEMS JSON_ARRAY_T;
        ORDER_ITEM JSON_OBJECT_T;
        V_TOTAL_CREDIT NUMBER;
        V_TOTAL_CREDIT_OLD NUMBER;
        V_USED_CREDIT_TYPE NUMBER;
        V_DEDUCTION_AMOUNT NUMBER;
        V_DEDUCTION_AMOUNT_REMAIN NUMBER;
        V_TOTAL_DEDUCTION_AMOUNT NUMBER := 0;
        V_CASH_AMOUNT NUMBER := 0;
        V_UNITAMOUNT NUMBER;
        V_WEIGHT NUMBER;
        V_ITEMS_PROCESSED BOOLEAN := FALSE;
        V_ASSIGNED_CREDITS VARCHAR2(4000); -- JSON array for assigned credits
        V_NAME VARCHAR2(50);
        V_UNIT_NAME VARCHAR2(50);
        
        -- Cursor to fetch credits
        CURSOR CREDITS_CURSOR IS
            SELECT CREDITTYPE, TOTALCREDIT
            FROM MSA_SCHEMA.CREDITS
            WHERE PARENTNATIONALCODE = V_NATIONAL_CODE
            AND CREDITTYPE IN (2, 3, 1)
            ORDER BY 
                CASE CREDITTYPE
                    WHEN 2 THEN 1
                    WHEN 3 THEN 2
                    ELSE 3
                END;
        
    BEGIN
        -- Initialize variables
        V_DEDUCTION_AMOUNT_REMAIN := 0;


        -- Check if JSON data is not null
        IF P_JSON_DATA IS NOT NULL THEN
            JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            
            -- Process JSON data
            IF JSON_DATA IS NOT NULL THEN
                -- Extract data from JSON
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_REQUEST_DATE := TO_DATE(JSON_DATA.GET_NUMBER('requestDate'), 'YYYYMMDDHH24MISS');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');               
                ORDER_ITEMS := JSON_DATA.GET_ARRAY('orderItems');
                V_ORDER_ID := MSA_SCHEMA.ITEMORDER_SEQ.NEXTVAL;
                
                -- Loop through credits
                FOR CREDIT_REC IN CREDITS_CURSOR LOOP
                    V_USED_CREDIT_TYPE := CREDIT_REC.CREDITTYPE;
                    V_TOTAL_CREDIT := CREDIT_REC.TOTALCREDIT;
                    
                    -- Loop through order items
                    FOR I IN 0..ORDER_ITEMS.GET_SIZE()-1 LOOP
                        IF V_TOTAL_CREDIT <= 0 THEN
                            FETCH CREDITS_CURSOR INTO V_USED_CREDIT_TYPE, V_TOTAL_CREDIT;
                            IF CREDITS_CURSOR%NOTFOUND THEN
                                EXIT;
                            END IF;
                        END IF;
                        
                        ORDER_ITEM := JSON_OBJECT_T(ORDER_ITEMS.GET(I));
                        IF ORDER_ITEM IS NOT NULL THEN
                            V_COMMODITY_CODE := ORDER_ITEM.GET_STRING('commodityCode');
                            V_QUANTITY := ORDER_ITEM.GET_NUMBER('quantity');
                            V_UNIT_CODE := ORDER_ITEM.GET_STRING('unitCode');
                            V_UNIT_CODE_INT := TO_NUMBER(V_UNIT_CODE);
                            V2_AMOUNT := ORDER_ITEM.GET_NUMBER('amount');
                            
                            SELECT GC.UNITAMOUNT, G.WEIGHT, GC."NAME"
                            INTO V_UNITAMOUNT, V_WEIGHT, V_NAME
                            FROM MSA_GOOD.GOODCATEGORIES GC, MSA_GOOD.GOODS G
                            WHERE GC.SALETYPE = V_USED_CREDIT_TYPE
                            AND G.CATEGORY = GC.ID
                            AND G.BARCODE = V_COMMODITY_CODE;

                            SELECT U.NAME INTO V_UNIT_NAME FROM MSA_SCHEMA.UNITS U
                            WHERE U.CODE=V_UNIT_CODE_INT;


                            V_DEDUCTION_AMOUNT := V_QUANTITY * V_UNITAMOUNT * V_WEIGHT;
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_DEDUCTION_AMOUNT + V_DEDUCTION_AMOUNT;
                            V_TOTAL_CREDIT_OLD := V_TOTAL_CREDIT;
                            
                            IF V_TOTAL_CREDIT > 0 THEN
                                IF V_TOTAL_CREDIT < V_DEDUCTION_AMOUNT THEN
                                    V_DEDUCTION_AMOUNT := V_TOTAL_CREDIT;
                                END IF;
                                
                                V_TOTAL_CREDIT := GREATEST(V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT, 0);
                                V_ITEMS_PROCESSED := TRUE;
                                
                                -- Append order item details to assigned credits JSON array
                                V_ASSIGNED_CREDITS := V_ASSIGNED_CREDITS || '{
                                    "commodityCode": "' || V_COMMODITY_CODE || '",
                                    "commodityName": "' || V_NAME || '", 
                                    "unitCode": "' || V_UNIT_CODE || '",
                                    "unitName": "' || V_UNIT_NAME || '",
                                    "assignedCredit": ' || V_DEDUCTION_AMOUNT || ',
                                    "currentCredit": ' || (V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT) || '
                                },';

                                V_CASH_AMOUNT := V_AMOUNT -  V_TOTAL_DEDUCTION_AMOUNT;                                
                                
                            END IF;
                        END IF;
                    END LOOP;
                    
                    EXIT WHEN V_ITEMS_PROCESSED = TRUE;
                    
                END LOOP;

                -- Remove trailing comma from assigned credits JSON array
                V_ASSIGNED_CREDITS := RTRIM(V_ASSIGNED_CREDITS, ',');
                
                -- Construct JSON response with assigned credits array
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": {
                            "rrn": "' || V_RRN || '",
                            "stan": "' || V_STAN || '",
                            "orderTrace": ' || V_ORDER_ID || ',
                            "terminalNumber": "' || V_TERMINAL_NUMBER || '",
                            "creditAmount": ' || V_TOTAL_CREDIT || ',
                            "amount": ' || V_AMOUNT || ',
                            "assignedCredits": [' || V_ASSIGNED_CREDITS || ']
                        }
                    }
                }';
                INSERT INTO MSA_SCHEMA.ORDERS (ORDERTRACE,RRN,STAN,V_NATIONAL_CODE,CARDNUMBER,TERMINAL,REQUESTDATE,RESPONSECODE,TRANSACTIONTYPE,CREDIT,PROVIDER,CREATEDATE,ASSIGNEDCREDIT,CASHAMOUNT)
                VALUES (V_ORDER_ID,V_RRN,V_STAN,V_NATIONAL_CODE,V_CARD_NUMBER,V_TERMINAL_NUMBER,V_REQUEST_DATE, '0' ,'100',V_AMOUNT, '555555', SYSDATE,V_TOTAL_DEDUCTION_AMOUNT,V_CASH_AMOUNT);

                COMMIT;
            END IF;
        END IF;       
    END ESTELAM;

    PROCEDURE PROCESS_JSON_DATA(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2) IS
        -- Declare variables
        V_RRN VARCHAR2(50);
        V_STAN VARCHAR2(50);
        V_NATIONAL_CODE VARCHAR2(100);
        V_CARD_NUMBER VARCHAR2(50);
        V_TERMINAL_NUMBER VARCHAR2(50);
        V_CHANNEL_TYPE NUMBER;
        V_REQUEST_DATE DATE;
        V_AMOUNT NUMBER;
        V2_AMOUNT NUMBER;
        V_COMMODITY_CODE VARCHAR2(50);
        V_QUANTITY NUMBER;
        V_UNIT_CODE VARCHAR2(10);
        V_UNIT_CODE_INT VARCHAR2(10);
        V_ORDER_ID NUMBER;
        JSON_DATA JSON_OBJECT_T;
        ORDER_ITEMS JSON_ARRAY_T;
        ORDER_ITEM JSON_OBJECT_T;
        V_TOTAL_CREDIT NUMBER;
        V_TOTAL_CREDIT_OLD NUMBER;
        V_USED_CREDIT_TYPE NUMBER;
        V_DEDUCTION_AMOUNT NUMBER;
        V_DEDUCTION_AMOUNT_REMAIN NUMBER;
        V_TOTAL_DEDUCTION_AMOUNT NUMBER := 0;
        V_CASH_AMOUNT NUMBER := 0;
        V_UNITAMOUNT NUMBER;
        V_WEIGHT NUMBER;
        V_ITEMS_PROCESSED BOOLEAN := FALSE;
        V_ASSIGNED_CREDITS VARCHAR2(4000); -- JSON array for assigned credits
        V_NAME VARCHAR2(50);
        V_UNIT_NAME VARCHAR2(50);
        
        CURSOR CREDITS_CURSOR IS
            SELECT CREDITTYPE, TOTALCREDIT
            FROM MSA_SCHEMA.CREDITS
            WHERE PARENTNATIONALCODE = V_NATIONAL_CODE
            AND CREDITTYPE IN (2, 3, 1)
            ORDER BY 
                CASE CREDITTYPE
                    WHEN 2 THEN 1
                    WHEN 3 THEN 2
                    ELSE 3
                END;
        
    BEGIN
        -- Initialize variables
        V_DEDUCTION_AMOUNT_REMAIN := 0;

        -- Check if JSON data is not null
        IF P_JSON_DATA IS NOT NULL THEN
            JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            
            -- Process JSON data
            IF JSON_DATA IS NOT NULL THEN
                -- Extract data from JSON
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_REQUEST_DATE := TO_DATE(JSON_DATA.GET_NUMBER('requestDate'), 'YYYYMMDDHH24MISS');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');               
                ORDER_ITEMS := JSON_DATA.GET_ARRAY('orderItems');
                --V_ORDER_ID := MSA_SCHEMA.ITEMORDER_SEQ.NEXTVAL;
                SELECT MAX(o.ORDERTRACE) INTO V_ORDER_ID
                FROM MSA_SCHEMA.ORDERS o
                WHERE o.RRN = V_RRN;
                
                -- Loop through credits
                FOR CREDIT_REC IN CREDITS_CURSOR LOOP
                    V_USED_CREDIT_TYPE := CREDIT_REC.CREDITTYPE;
                    V_TOTAL_CREDIT := CREDIT_REC.TOTALCREDIT;
                    -- Reset flag for each credit
                    
                    -- Loop through order items
                    FOR I IN 0..ORDER_ITEMS.GET_SIZE()-1 LOOP
                        IF V_TOTAL_CREDIT <= 0 THEN  -- Fetch the next credit if total credit is zero

                            FETCH CREDITS_CURSOR INTO V_USED_CREDIT_TYPE, V_TOTAL_CREDIT;
                            IF CREDITS_CURSOR%NOTFOUND THEN
                            
                                EXIT; -- Exit processing if no more credits available
                            END IF;
                            -- Reset flag for the new credit
                        END IF;
                        
                        ORDER_ITEM := JSON_OBJECT_T(ORDER_ITEMS.GET(I));
                        IF ORDER_ITEM IS NOT NULL THEN
                            -- Extract order item data
                            V_COMMODITY_CODE := ORDER_ITEM.GET_STRING('commodityCode');
                            V_QUANTITY := ORDER_ITEM.GET_NUMBER('quantity');
                            V_UNIT_CODE := ORDER_ITEM.GET_STRING('unitCode');
                            V_UNIT_CODE_INT := TO_NUMBER(V_UNIT_CODE);
                            V2_AMOUNT := ORDER_ITEM.GET_NUMBER('amount');
                            
                            -- Get unit amount and weight from goods table
                            SELECT GC.UNITAMOUNT, G.WEIGHT, GC."NAME"
                            INTO V_UNITAMOUNT, V_WEIGHT, V_NAME
                            FROM MSA_GOOD.GOODCATEGORIES GC, MSA_GOOD.GOODS G
                            WHERE GC.SALETYPE = V_USED_CREDIT_TYPE
                            AND G.CATEGORY = GC.ID
                            AND G.BARCODE = V_COMMODITY_CODE;

                            SELECT U.NAME INTO V_UNIT_NAME FROM MSA_SCHEMA.UNITS U
                            WHERE U.CODE=V_UNIT_CODE_INT;

                            -- Calculate deduction amount based on quantity, unit amount, and weight
                            V_DEDUCTION_AMOUNT := V_QUANTITY * V_UNITAMOUNT * V_WEIGHT;
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_DEDUCTION_AMOUNT + V_DEDUCTION_AMOUNT;
                            V_TOTAL_CREDIT_OLD := V_TOTAL_CREDIT;
                            
                            -- Deduct from total credit if available
                            IF V_TOTAL_CREDIT > 0 THEN
                                -- Adjust deduction amount if needed
                                IF V_TOTAL_CREDIT < V_DEDUCTION_AMOUNT THEN
                                    V_DEDUCTION_AMOUNT := V_TOTAL_CREDIT;
                                END IF;

                                V_ASSIGNED_CREDITS := V_ASSIGNED_CREDITS || '{
                                    "commodityCode": "' || V_COMMODITY_CODE || '",
                                    "commodityName": "' || V_NAME || '", 
                                    "unitCode": "' || V_UNIT_CODE || '",
                                    "unitName": "' || V_UNIT_NAME || '",
                                    "assignedCredit": ' || V_DEDUCTION_AMOUNT || ',
                                    "currentCredit": ' || (V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT) || '
                                },';

                                V_CASH_AMOUNT := V_AMOUNT -  V_TOTAL_DEDUCTION_AMOUNT;
                                
                                -- Update total credit
                                V_TOTAL_CREDIT := GREATEST(V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT, 0);
                                V_ITEMS_PROCESSED := TRUE;

                                                                -- Append order item details to assigned credits JSON array

                                
                                -- Update total credit in the database
                                UPDATE MSA_SCHEMA.CREDITS
                                SET TOTALCREDIT = V_TOTAL_CREDIT,
                                LATESTTOTALCREDIT = V_TOTAL_CREDIT_OLD
                                WHERE PARENTNATIONALCODE = V_NATIONAL_CODE
                                AND CREDITTYPE = V_USED_CREDIT_TYPE;
                                
                                -- Insert into ITEMORDER table
                                INSERT INTO MSA_SCHEMA.ITEMORDER (ORDER_ID, RRN, STAN, NATIONAL_CODE, CARD_NUMBER, TERMINAL_NUMBER, CHANNEL_TYPE, REQUEST_DATE, AMOUNT, COMMODITY_CODE, QUANTITY, UNIT_CODE, AMOUNT_DETAIL,ASSIGNCREDIT,CREDITTYPE)
                                VALUES (V_ORDER_ID, V_RRN, V_STAN, V_NATIONAL_CODE, V_CARD_NUMBER, V_TERMINAL_NUMBER, V_CHANNEL_TYPE, V_REQUEST_DATE, V_AMOUNT, V_COMMODITY_CODE, V_QUANTITY, V_UNIT_CODE, V2_AMOUNT,V_DEDUCTION_AMOUNT, V_USED_CREDIT_TYPE);
                            END IF;
                        END IF;
                    END LOOP;  -- End of ORDER_ITEMS loop
                    
                    -- Exit loop if all purchase items have been processed for the current credit
                    EXIT WHEN V_ITEMS_PROCESSED = TRUE;
                    
                END LOOP; -- End of CREDITS_CURSOR loop

                V_ASSIGNED_CREDITS := RTRIM(V_ASSIGNED_CREDITS, ',');
                
                -- Construct JSON response with assigned credits array
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": {
                            "rrn": "' || V_RRN || '",
                            "stan": "' || V_STAN || '",
                            "orderTrace": ' || V_ORDER_ID || ',
                            "terminalNumber": "' || V_TERMINAL_NUMBER || '",
                            "creditAmount": ' || V_TOTAL_CREDIT || ',
                            "amount": ' || V_AMOUNT || ',
                            "assignedCredits": [' || V_ASSIGNED_CREDITS || ']
                        }
                    }
                }';

                INSERT INTO MSA_SCHEMA.ORDERS (ORDERTRACE,RRN,STAN,V_NATIONAL_CODE,CARDNUMBER,TERMINAL,REQUESTDATE,RESPONSECODE,TRANSACTIONTYPE,CREDIT,PROVIDER,CREATEDATE,ASSIGNEDCREDIT,CASHAMOUNT)
                VALUES (V_ORDER_ID,V_RRN,V_STAN,V_NATIONAL_CODE,V_CARD_NUMBER,V_TERMINAL_NUMBER,V_REQUEST_DATE, '0' ,'200',V_AMOUNT, '555555', SYSDATE,V_TOTAL_DEDUCTION_AMOUNT,V_CASH_AMOUNT);
                COMMIT;
            END IF;
        END IF;       
    END PROCESS_JSON_DATA;


    PROCEDURE CONFIRM_ORDER(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2) IS
        JSON_DATA JSON_OBJECT_T;
        V_ORDER_ID NUMBER;
        V_CHANNEL_TYPE NUMBER;
        V_RRN VARCHAR2(50); 
        V_STAN VARCHAR2(50); 
        V1_NATIONAL_CODE VARCHAR2(100);
        V_CARD_NUMBER VARCHAR2(50);
        V_TERMINAL_NUMBER VARCHAR2(50);
        V_CREDITAMOUNT NUMBER;
        V_AMOUNT NUMBER;
        TYPE order_cursor_type IS REF CURSOR;
        v_cursor order_cursor_type;
        TMP_RRN MSA_SCHEMA.ORDERS.RRN%TYPE;
        TMP_STAN MSA_SCHEMA.ORDERS.STAN%TYPE;
        TMP_V_NATIONAL_CODE MSA_SCHEMA.ORDERS.V_NATIONAL_CODE%TYPE;
        TMP_CARDNUMBER MSA_SCHEMA.ORDERS.CARDNUMBER%TYPE;
        TMP_TERMINAL MSA_SCHEMA.ORDERS.TERMINAL%TYPE;
        TMP_ORDERTRACE MSA_SCHEMA.ORDERS.ORDERTRACE%TYPE;
        TMP_RESPONSECODE MSA_SCHEMA.ORDERS.RESPONSECODE%TYPE;
        TMP_TRANSACTIONTYPE MSA_SCHEMA.ORDERS.TRANSACTIONTYPE%TYPE;
        TMP_CREDIT MSA_SCHEMA.ORDERS.CREDIT%TYPE;
        TMP_PROVIDER MSA_SCHEMA.ORDERS.PROVIDER%TYPE;
        TMP_CREATEDATE MSA_SCHEMA.ORDERS.CREATEDATE%TYPE;
        TMP_ASSIGNEDCREDIT MSA_SCHEMA.ORDERS.ASSIGNEDCREDIT%TYPE;
        TMP_CASHAMOUNT MSA_SCHEMA.ORDERS.CASHAMOUNT%TYPE;
        TMP_REQUESTDATE MSA_SCHEMA.ORDERS.REQUESTDATE%TYPE;

BEGIN
            IF P_JSON_DATA IS NOT NULL THEN
                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
                
                -- Process JSON data
                IF JSON_DATA IS NOT NULL THEN
                     V_ORDER_ID := JSON_DATA.GET_NUMBER('orderTrace');
                     V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                     V_RRN := JSON_DATA.GET_STRING('rrn');
                     V_STAN := JSON_DATA.GET_STRING('stan');
                     V1_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                     V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                     V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                     V_CREDITAMOUNT := JSON_DATA.GET_NUMBER('creditAmount');
                     V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                     OPEN v_cursor FOR
                        SELECT * FROM MSA_SCHEMA.ORDERS o
                        WHERE o.ORDERTRACE = V_ORDER_ID
                        AND o.RRN = V_RRN
                        AND o.STAN = V_STAN
                        AND o.V_NATIONAL_CODE = V1_NATIONAL_CODE
                        AND o.TERMINAL = V_TERMINAL_NUMBER
                        AND o.TRANSACTIONTYPE='200';

                    LOOP 
                        FETCH v_cursor INTO 
                        TMP_RRN,TMP_STAN,TMP_V_NATIONAL_CODE,TMP_CARDNUMBER,TMP_TERMINAL,TMP_ORDERTRACE,TMP_RESPONSECODE,TMP_TRANSACTIONTYPE,
                        TMP_CREDIT,TMP_PROVIDER,TMP_CREATEDATE,TMP_ASSIGNEDCREDIT,TMP_CASHAMOUNT,TMP_REQUESTDATE;
                        EXIT WHEN v_cursor%NOTFOUND;
                        -- Check if the record doesn't already exist in MSA_SCHEMA.ORDERS table before inserting
                        INSERT INTO MSA_SCHEMA.ORDERS (ORDERTRACE,RRN,STAN,V_NATIONAL_CODE,CARDNUMBER,TERMINAL,REQUESTDATE,RESPONSECODE,TRANSACTIONTYPE,CREDIT,PROVIDER,CREATEDATE,ASSIGNEDCREDIT,CASHAMOUNT)
                        VALUES (TMP_ORDERTRACE,TMP_RRN,TMP_STAN,TMP_V_NATIONAL_CODE,TMP_CARDNUMBER,TMP_TERMINAL,TMP_REQUESTDATE,TMP_RESPONSECODE,'220',
                        TMP_CREDIT,TMP_PROVIDER,TMP_CREATEDATE,TMP_ASSIGNEDCREDIT,TMP_CASHAMOUNT);
                    END LOOP;
                    COMMIT;
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": TRUE/FALSE
                        }
                        }';
                    
        END IF;
END IF;
END CONFIRM_ORDER;

    PROCEDURE REVERSE_ORDER_DISTRIBUTION(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2) IS
        -- Procedure to reverse the order distribution and return amounts back to credits
        JSON_DATA JSON_OBJECT_T;
        V_ORDER_ID NUMBER;
        V_CHANNEL_TYPE NUMBER;
        V_RRN VARCHAR2(50); 
        V_STAN VARCHAR2(50); 
        V1_NATIONAL_CODE VARCHAR2(100);
        V_CARD_NUMBER VARCHAR2(50);
        V_TERMINAL_NUMBER VARCHAR2(50);
        V_CREDITAMOUNT NUMBER;
        V_AMOUNT NUMBER;
        TYPE order_cursor_type IS REF CURSOR;
        v_cursor order_cursor_type;
        TMP_RRN MSA_SCHEMA.ORDERS.RRN%TYPE;
        TMP_STAN MSA_SCHEMA.ORDERS.STAN%TYPE;
        TMP_V_NATIONAL_CODE MSA_SCHEMA.ORDERS.V_NATIONAL_CODE%TYPE;
        TMP_CARDNUMBER MSA_SCHEMA.ORDERS.CARDNUMBER%TYPE;
        TMP_TERMINAL MSA_SCHEMA.ORDERS.TERMINAL%TYPE;
        TMP_ORDERTRACE MSA_SCHEMA.ORDERS.ORDERTRACE%TYPE;
        TMP_RESPONSECODE MSA_SCHEMA.ORDERS.RESPONSECODE%TYPE;
        TMP_TRANSACTIONTYPE MSA_SCHEMA.ORDERS.TRANSACTIONTYPE%TYPE;
        TMP_CREDIT MSA_SCHEMA.ORDERS.CREDIT%TYPE;
        TMP_PROVIDER MSA_SCHEMA.ORDERS.PROVIDER%TYPE;
        TMP_CREATEDATE MSA_SCHEMA.ORDERS.CREATEDATE%TYPE;
        TMP_ASSIGNEDCREDIT MSA_SCHEMA.ORDERS.ASSIGNEDCREDIT%TYPE;
        TMP_CASHAMOUNT MSA_SCHEMA.ORDERS.CASHAMOUNT%TYPE;
        TMP_REQUESTDATE MSA_SCHEMA.ORDERS.REQUESTDATE%TYPE;   
    BEGIN
    IF P_JSON_DATA IS NOT NULL THEN
                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
                
                -- Process JSON data
                IF JSON_DATA IS NOT NULL THEN
                     V_ORDER_ID := JSON_DATA.GET_NUMBER('orderTrace');
                     V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                     V_RRN := JSON_DATA.GET_STRING('rrn');
                     V_STAN := JSON_DATA.GET_STRING('stan');
                     V1_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                     V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                     V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                     V_CREDITAMOUNT := JSON_DATA.GET_NUMBER('creditAmount');
                     V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                     OPEN v_cursor FOR
                        SELECT * FROM MSA_SCHEMA.ORDERS o
                        WHERE o.ORDERTRACE = V_ORDER_ID
                        AND o.RRN = V_RRN
                        AND o.STAN = V_STAN
                        AND o.V_NATIONAL_CODE = V1_NATIONAL_CODE
                        AND o.TERMINAL = V_TERMINAL_NUMBER
                        AND o.TRANSACTIONTYPE='200';
                LOOP 
                        FETCH v_cursor INTO 
                        TMP_RRN,TMP_STAN,TMP_V_NATIONAL_CODE,TMP_CARDNUMBER,TMP_TERMINAL,TMP_ORDERTRACE,TMP_RESPONSECODE,TMP_TRANSACTIONTYPE,
                        TMP_CREDIT,TMP_PROVIDER,TMP_CREATEDATE,TMP_ASSIGNEDCREDIT,TMP_CASHAMOUNT,TMP_REQUESTDATE;
                        EXIT WHEN v_cursor%NOTFOUND;
                        -- Check if the record doesn't already exist in MSA_SCHEMA.ORDERS table before inserting
                        INSERT INTO MSA_SCHEMA.ORDERS (ORDERTRACE,RRN,STAN,V_NATIONAL_CODE,CARDNUMBER,TERMINAL,REQUESTDATE,RESPONSECODE,TRANSACTIONTYPE,CREDIT,PROVIDER,CREATEDATE,ASSIGNEDCREDIT,CASHAMOUNT)
                        VALUES (TMP_ORDERTRACE,TMP_RRN,TMP_STAN,TMP_V_NATIONAL_CODE,TMP_CARDNUMBER,TMP_TERMINAL,TMP_REQUESTDATE,TMP_RESPONSECODE,'420',
                        TMP_CREDIT,TMP_PROVIDER,TMP_CREATEDATE,TMP_ASSIGNEDCREDIT,TMP_CASHAMOUNT);
                    END LOOP;
                    COMMIT;
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": TRUE/FALSE
                        }
                        }';
                    
        END IF;
END IF;

        --FETCH order_cur INTO ORDER_RECORD;
        FOR r in (SELECT ORDER_ID, NATIONAL_CODE, CREDITTYPE, sum(ASSIGNCREDIT) ASSIGNCREDIT
            FROM MSA_SCHEMA.ITEMORDER
            WHERE ORDER_ID = V_ORDER_ID
            GROUP BY ORDER_ID, NATIONAL_CODE, CREDITTYPE) LOOP
        
        UPDATE MSA_SCHEMA.CREDITS
        SET TOTALCREDIT = TOTALCREDIT + r.ASSIGNCREDIT
            WHERE PARENTNATIONALCODE = r.NATIONAL_CODE
        AND CREDITTYPE = r.CREDITTYPE;
        COMMIT;
        END LOOP;

    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            DBMS_OUTPUT.PUT_LINE('No data found for the given order ID');
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('An error occurred: ' || SQLERRM);
    END REVERSE_ORDER_DISTRIBUTION;
    
END PKG_ORDER;


CREATE OR REPLACE PACKAGE "MSA_SCHEMA".PKG_ORDER_RECEIPT AS
    PROCEDURE ESTELAM_100_CODE(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE ORDER_200_CODE(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE CONFIRM_220_CODE_ORDER(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
    PROCEDURE REVERSE_420_CODE_ORDER(P_JSON_DATA IN VARCHAR2, P_RESPONSE OUT VARCHAR2);
END PKG_ORDER_RECEIPT;


CREATE OR REPLACE PACKAGE BODY "MSA_SCHEMA".PKG_ORDER_RECEIPT AS


    PROCEDURE ESTELAM_100_CODE(
        P_JSON_DATA IN VARCHAR2,
        P_RESPONSE OUT VARCHAR2
    ) IS
        V_RRN                     VARCHAR2(50);
        V_STAN                    VARCHAR2(50);
        V_NATIONAL_CODE           VARCHAR2(100);
        V_CARD_NUMBER             VARCHAR2(50);
        V_TERMINAL_NUMBER         VARCHAR2(50);
        V_CHANNEL_TYPE            NUMBER;
        V_REQUEST_DATE            DATE;
        V_AMOUNT                  NUMBER;
        V2_AMOUNT                 NUMBER;
        V_COMMODITY_CODE          VARCHAR2(50);
        V_QUANTITY                NUMBER;
        V_UNIT_CODE               VARCHAR2(10);
        V_UNIT_CODE_INT           VARCHAR2(10);
        V_ORDER_ID                NUMBER;
        JSON_DATA                 JSON_OBJECT_T;
        ORDER_ITEMS               JSON_ARRAY_T;
        ORDER_ITEM                JSON_OBJECT_T;
        V_TOTAL_CREDIT            NUMBER;
        V_TOTAL_CREDIT_OLD        NUMBER;
        V_USED_CREDIT_TYPE        NUMBER;
        V_DEDUCTION_AMOUNT        NUMBER;
        V_DEDUCTION_AMOUNT_REMAIN NUMBER :=0;
        V_TOTAL_DEDUCTION_AMOUNT  NUMBER := 0;
        V_CASH_AMOUNT             NUMBER := 0;
        V_UNITAMOUNT              NUMBER;
        V_WEIGHT                  NUMBER;
        V_ITEMS_PROCESSED         BOOLEAN := FALSE;
        V_ASSIGNED_CREDITS        VARCHAR2(4000);
        V_NAME                    VARCHAR2(50);
        V_UNIT_NAME               VARCHAR2(50);
        V_ERROR_MSG               VARCHAR2(200);

        CURSOR CREDITS_CURSOR IS
        SELECT
            CREDITTYPE,
            TOTALCREDIT
        FROM
            MSA_SCHEMA.CREDITS
        WHERE
            PARENTNATIONALCODE = V_NATIONAL_CODE
            AND CREDITTYPE IN (2, 3, 1)
        ORDER BY
            CASE CREDITTYPE
                WHEN 2 THEN
                    1
                WHEN 3 THEN
                    2
                ELSE
                    3
            END;

    BEGIN

        V_ERROR_MSG := '';

        IF P_JSON_DATA IS NULL THEN
                    V_ERROR_MSG := 'Error: JSON data is missing.';
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';
        ELSE
            BEGIN

                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            EXCEPTION
                WHEN OTHERS THEN
                    V_ERROR_MSG := 'Error: Invalid JSON data format.';
            END;
            IF V_ERROR_MSG IS NULL THEN

            IF JSON_DATA IS NOT NULL THEN
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_REQUEST_DATE := TO_DATE(JSON_DATA.GET_NUMBER('requestDate'), 'YYYYMMDDHH24MISS');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                ORDER_ITEMS := JSON_DATA.GET_ARRAY('orderItems');
                V_ORDER_ID := MSA_SCHEMA.ITEMORDER_SEQ.NEXTVAL;

                FOR CREDIT_REC IN CREDITS_CURSOR LOOP
                    V_USED_CREDIT_TYPE := CREDIT_REC.CREDITTYPE;
                    V_TOTAL_CREDIT := CREDIT_REC.TOTALCREDIT;

                    FOR I IN 0..ORDER_ITEMS.GET_SIZE()-1 LOOP
                        IF V_TOTAL_CREDIT <= 0 THEN
                            FETCH CREDITS_CURSOR INTO V_USED_CREDIT_TYPE, V_TOTAL_CREDIT;
                            IF CREDITS_CURSOR%NOTFOUND THEN
                                EXIT;
                            END IF;
                        END IF;

                        ORDER_ITEM := JSON_OBJECT_T(ORDER_ITEMS.GET(I));
                        IF ORDER_ITEM IS NOT NULL THEN
                            V_COMMODITY_CODE := ORDER_ITEM.GET_STRING('commodityCode');
                            V_QUANTITY := ORDER_ITEM.GET_NUMBER('quantity');
                            V_UNIT_CODE := ORDER_ITEM.GET_STRING('unitCode');
                            V_UNIT_CODE_INT := TO_NUMBER(V_UNIT_CODE);
                            V2_AMOUNT := ORDER_ITEM.GET_NUMBER('amount');
                            SELECT
                                GC.UNITAMOUNT,
                                G.WEIGHT,
                                GC."NAME" INTO V_UNITAMOUNT,
                                V_WEIGHT,
                                V_NAME
                            FROM
                                MSA_GOOD.GOODCATEGORIES GC,
                                MSA_GOOD.GOODS          G
                            WHERE
                                GC.SALETYPE = V_USED_CREDIT_TYPE
                                AND G.CATEGORY = GC.ID
                                AND G.BARCODE = V_COMMODITY_CODE;
                            SELECT
                                U.NAME INTO V_UNIT_NAME
                            FROM
                                MSA_SCHEMA.UNITS U
                            WHERE
                                U.CODE=V_UNIT_CODE_INT;
                            V_DEDUCTION_AMOUNT := V_QUANTITY * V_UNITAMOUNT * V_WEIGHT;
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_DEDUCTION_AMOUNT + V_DEDUCTION_AMOUNT;
                            V_TOTAL_CREDIT_OLD := V_TOTAL_CREDIT;
                            V_ASSIGNED_CREDITS := V_ASSIGNED_CREDITS || '{
                                "commodityCode": "' || V_COMMODITY_CODE || '",
                                "commodityName": "' || V_NAME || '",
                                "unitCode": "' || V_UNIT_CODE || '",
                                "unitName": "' || V_UNIT_NAME || '",
                                "assignedCredit": ' || V_DEDUCTION_AMOUNT || ',
                                "currentCredit": ' || (V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT) || '
                            },';
                            V_CASH_AMOUNT := V_AMOUNT - V_TOTAL_DEDUCTION_AMOUNT;
                        END IF;
                    END LOOP;

                    IF V_TOTAL_CREDIT > 0 THEN
                        IF V_TOTAL_CREDIT < V_TOTAL_DEDUCTION_AMOUNT THEN
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_CREDIT;
                        END IF;

                        V_TOTAL_CREDIT := GREATEST(V_TOTAL_CREDIT - V_TOTAL_DEDUCTION_AMOUNT, 0);
                        V_ITEMS_PROCESSED := TRUE;
                    END IF;

                    EXIT WHEN V_ITEMS_PROCESSED = TRUE;
                END LOOP;

                V_ASSIGNED_CREDITS := RTRIM(V_ASSIGNED_CREDITS, ',');

                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": {
                            "rrn": "' || V_RRN || '",
                            "stan": "' || V_STAN || '",
                            "orderTrace": ' || V_ORDER_ID || ',
                            "terminalNumber": "' || V_TERMINAL_NUMBER || '",
                            "creditAmount": ' || V_TOTAL_CREDIT || ',
                            "amount": ' || V_AMOUNT || ',
                            "assignedCredits": [' || V_ASSIGNED_CREDITS || ']
                        }
                    }
                }';

                INSERT INTO MSA_SCHEMA.ORDERS (
                    ORDERTRACE,
                    RRN,
                    STAN,
                    V_NATIONAL_CODE,
                    CARDNUMBER,
                    TERMINAL,
                    REQUESTDATE,
                    RESPONSECODE,
                    TRANSACTIONTYPE,
                    CREDIT,
                    PROVIDER,
                    CREATEDATE,
                    ASSIGNEDCREDIT,
                    CASHAMOUNT
                ) VALUES (
                    V_ORDER_ID,
                    V_RRN,
                    V_STAN,
                    V_NATIONAL_CODE,
                    V_CARD_NUMBER,
                    V_TERMINAL_NUMBER,
                    V_REQUEST_DATE,
                    '0',
                    '100',
                    V_AMOUNT,
                    '555555',
                    SYSDATE,
                    V_TOTAL_DEDUCTION_AMOUNT,
                    V_CASH_AMOUNT
                );
                COMMIT;
            END IF;
        ELSE
            P_RESPONSE := '{"error": "' || V_ERROR_MSG || '"}';
        END IF;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
 -- Set error message for unexpected errors
        V_ERROR_MSG := 'Error: '
                       || SQLERRM;
 -- Return the error message
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';
END ESTELAM_100_CODE;


    PROCEDURE ORDER_200_CODE(
        P_JSON_DATA IN VARCHAR2,
        P_RESPONSE OUT VARCHAR2
    ) IS
        V_RRN                     VARCHAR2(50);
        V_STAN                    VARCHAR2(50);
        V_NATIONAL_CODE           VARCHAR2(100);
        V_CARD_NUMBER             VARCHAR2(50);
        V_TERMINAL_NUMBER         VARCHAR2(50);
        V_CHANNEL_TYPE            NUMBER;
        V_REQUEST_DATE            DATE;
        V_AMOUNT                  NUMBER;
        V2_AMOUNT                 NUMBER;
        V_COMMODITY_CODE          VARCHAR2(50);
        V_QUANTITY                NUMBER;
        V_UNIT_CODE               VARCHAR2(10);
        V_UNIT_CODE_INT           VARCHAR2(10);
        V_ORDER_ID                NUMBER;
        JSON_DATA                 JSON_OBJECT_T;
        ORDER_ITEMS               JSON_ARRAY_T;
        ORDER_ITEM                JSON_OBJECT_T;
        V_TOTAL_CREDIT            NUMBER;
        V_TOTAL_CREDIT_OLD        NUMBER;
        V_USED_CREDIT_TYPE        NUMBER;
        V_DEDUCTION_AMOUNT        NUMBER;
        V_DEDUCTION_AMOUNT_REMAIN NUMBER :=0;
        V_TOTAL_DEDUCTION_AMOUNT  NUMBER := 0;
        V_CASH_AMOUNT             NUMBER := 0;
        V_UNITAMOUNT              NUMBER;
        V_WEIGHT                  NUMBER;
        V_ITEMS_PROCESSED         BOOLEAN := FALSE;
        V_ASSIGNED_CREDITS        VARCHAR2(4000);
        V_NAME                    VARCHAR2(50);
        V_UNIT_NAME               VARCHAR2(50);
        V_ERROR_MSG               VARCHAR2(200);

        CURSOR CREDITS_CURSOR IS
        SELECT
            CREDITTYPE,
            TOTALCREDIT
        FROM
            MSA_SCHEMA.CREDITS
        WHERE
            PARENTNATIONALCODE = V_NATIONAL_CODE
            AND CREDITTYPE IN (2, 3, 1)
        ORDER BY
            CASE CREDITTYPE
                WHEN 2 THEN
                    1
                WHEN 3 THEN
                    2
                ELSE
                    3
            END;

    BEGIN

        V_ERROR_MSG := '';

        IF P_JSON_DATA IS NULL THEN
                    V_ERROR_MSG := 'Error: JSON data is missing.';
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';
        ELSE
            BEGIN
                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            EXCEPTION
                WHEN OTHERS THEN
                    V_ERROR_MSG := 'Error: Invalid JSON data format.';
            END;
            IF V_ERROR_MSG IS NULL THEN
            IF JSON_DATA IS NOT NULL THEN
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_REQUEST_DATE := TO_DATE(JSON_DATA.GET_NUMBER('requestDate'), 'YYYYMMDDHH24MISS');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                ORDER_ITEMS := JSON_DATA.GET_ARRAY('orderItems');
                SELECT MAX(o.ORDERTRACE) INTO V_ORDER_ID
                FROM MSA_SCHEMA.ORDERS o
                WHERE o.RRN = V_RRN;

                FOR CREDIT_REC IN CREDITS_CURSOR LOOP
                    V_USED_CREDIT_TYPE := CREDIT_REC.CREDITTYPE;
                    V_TOTAL_CREDIT := CREDIT_REC.TOTALCREDIT;

                    FOR I IN 0..ORDER_ITEMS.GET_SIZE()-1 LOOP
                        IF V_TOTAL_CREDIT <= 0 THEN
                            FETCH CREDITS_CURSOR INTO V_USED_CREDIT_TYPE, V_TOTAL_CREDIT;
                            IF CREDITS_CURSOR%NOTFOUND THEN
                                EXIT;
                            END IF;
                        END IF;

                        ORDER_ITEM := JSON_OBJECT_T(ORDER_ITEMS.GET(I));
                        IF ORDER_ITEM IS NOT NULL THEN
                            V_COMMODITY_CODE := ORDER_ITEM.GET_STRING('commodityCode');
                            V_QUANTITY := ORDER_ITEM.GET_NUMBER('quantity');
                            V_UNIT_CODE := ORDER_ITEM.GET_STRING('unitCode');
                            V_UNIT_CODE_INT := TO_NUMBER(V_UNIT_CODE);
                            V2_AMOUNT := ORDER_ITEM.GET_NUMBER('amount');
                            SELECT
                                GC.UNITAMOUNT,
                                G.WEIGHT,
                                GC."NAME" INTO V_UNITAMOUNT,
                                V_WEIGHT,
                                V_NAME
                            FROM
                                MSA_GOOD.GOODCATEGORIES GC,
                                MSA_GOOD.GOODS          G
                            WHERE
                                GC.SALETYPE = V_USED_CREDIT_TYPE
                                AND G.CATEGORY = GC.ID
                                AND G.BARCODE = V_COMMODITY_CODE;
                            SELECT
                                U.NAME INTO V_UNIT_NAME
                            FROM
                                MSA_SCHEMA.UNITS U
                            WHERE
                                U.CODE=V_UNIT_CODE_INT;
                            V_DEDUCTION_AMOUNT := V_QUANTITY * V_UNITAMOUNT * V_WEIGHT;
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_DEDUCTION_AMOUNT + V_DEDUCTION_AMOUNT;
                            V_TOTAL_CREDIT_OLD := V_TOTAL_CREDIT;
                            V_ASSIGNED_CREDITS := V_ASSIGNED_CREDITS || '{
                                "commodityCode": "' || V_COMMODITY_CODE || '",
                                "commodityName": "' || V_NAME || '",
                                "unitCode": "' || V_UNIT_CODE || '",
                                "unitName": "' || V_UNIT_NAME || '",
                                "assignedCredit": ' || V_DEDUCTION_AMOUNT || ',
                                "currentCredit": ' || (V_TOTAL_CREDIT - V_DEDUCTION_AMOUNT) || '
                            },';
                            V_CASH_AMOUNT := V_AMOUNT - V_TOTAL_DEDUCTION_AMOUNT;
                            INSERT INTO MSA_SCHEMA.ITEMORDER (ORDER_ID, RRN, STAN, NATIONAL_CODE, CARD_NUMBER, TERMINAL_NUMBER, CHANNEL_TYPE, REQUEST_DATE, AMOUNT, COMMODITY_CODE, QUANTITY, UNIT_CODE, AMOUNT_DETAIL,ASSIGNCREDIT,CREDITTYPE)
                            VALUES (V_ORDER_ID, V_RRN, V_STAN, V_NATIONAL_CODE, V_CARD_NUMBER, V_TERMINAL_NUMBER, V_CHANNEL_TYPE, V_REQUEST_DATE, V_AMOUNT, V_COMMODITY_CODE, V_QUANTITY, V_UNIT_CODE, V2_AMOUNT,V_TOTAL_DEDUCTION_AMOUNT, V_USED_CREDIT_TYPE);
                        END IF;
                    END LOOP;

                    IF V_TOTAL_CREDIT > 0 THEN
                        IF V_TOTAL_CREDIT < V_TOTAL_DEDUCTION_AMOUNT THEN
                            V_TOTAL_DEDUCTION_AMOUNT := V_TOTAL_CREDIT;
                        END IF;

                        V_TOTAL_CREDIT := GREATEST(V_TOTAL_CREDIT - V_TOTAL_DEDUCTION_AMOUNT, 0);
                        V_ITEMS_PROCESSED := TRUE;
                        UPDATE MSA_SCHEMA.CREDITS
                        SET TOTALCREDIT = V_TOTAL_CREDIT,
                        LATESTTOTALCREDIT = V_TOTAL_CREDIT_OLD
                        WHERE PARENTNATIONALCODE = V_NATIONAL_CODE
                        AND CREDITTYPE = V_USED_CREDIT_TYPE;
                                
                                -- Insert into ITEMORDER table
 
                    END IF;

                    EXIT WHEN V_ITEMS_PROCESSED = TRUE;
                END LOOP;

                V_ASSIGNED_CREDITS := RTRIM(V_ASSIGNED_CREDITS, ',');

                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": {
                            "rrn": "' || V_RRN || '",
                            "stan": "' || V_STAN || '",
                            "orderTrace": ' || V_ORDER_ID || ',
                            "terminalNumber": "' || V_TERMINAL_NUMBER || '",
                            "creditAmount": ' || V_TOTAL_CREDIT || ',
                            "amount": ' || V_AMOUNT || ',
                            "assignedCredits": [' || V_ASSIGNED_CREDITS || ']
                        }
                    }
                }';

                INSERT INTO MSA_SCHEMA.ORDERS (
                    ORDERTRACE,
                    RRN,
                    STAN,
                    V_NATIONAL_CODE,
                    CARDNUMBER,
                    TERMINAL,
                    REQUESTDATE,
                    RESPONSECODE,
                    TRANSACTIONTYPE,
                    CREDIT,
                    PROVIDER,
                    CREATEDATE,
                    ASSIGNEDCREDIT,
                    CASHAMOUNT
                ) VALUES (
                    V_ORDER_ID,
                    V_RRN,
                    V_STAN,
                    V_NATIONAL_CODE,
                    V_CARD_NUMBER,
                    V_TERMINAL_NUMBER,
                    V_REQUEST_DATE,
                    '0',
                    '200',
                    V_AMOUNT,
                    '555555',
                    SYSDATE,
                    V_TOTAL_DEDUCTION_AMOUNT,
                    V_CASH_AMOUNT
                );
                COMMIT;
            END IF;
        ELSE
            P_RESPONSE := '{"error": "' || V_ERROR_MSG || '"}';
        END IF;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
 -- Set error message for unexpected errors
        V_ERROR_MSG := 'Error: '
                       || SQLERRM;
 -- Return the error message
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';       
END ORDER_200_CODE;


    PROCEDURE CONFIRM_220_CODE_ORDER(
        P_JSON_DATA IN VARCHAR2,
        P_RESPONSE OUT VARCHAR2
    ) IS
        JSON_DATA           JSON_OBJECT_T;
        V_ORDER_ID          NUMBER;
        V_CHANNEL_TYPE      NUMBER;
        V_RRN               VARCHAR2(50);
        V_STAN              VARCHAR2(50);
        V1_NATIONAL_CODE    VARCHAR2(100);
        V_CARD_NUMBER       VARCHAR2(50);
        V_TERMINAL_NUMBER   VARCHAR2(50);
        V_CREDITAMOUNT      NUMBER;
        V_AMOUNT            NUMBER;
        V_ERROR_MSG         VARCHAR2(200);
        TYPE ORDER_CURSOR_TYPE IS
            REF CURSOR;
        V_CURSOR            ORDER_CURSOR_TYPE;
        TMP_RRN             MSA_SCHEMA.ORDERS.RRN%TYPE;
        TMP_STAN            MSA_SCHEMA.ORDERS.STAN%TYPE;
        TMP_V_NATIONAL_CODE MSA_SCHEMA.ORDERS.V_NATIONAL_CODE%TYPE;
        TMP_CARDNUMBER      MSA_SCHEMA.ORDERS.CARDNUMBER%TYPE;
        TMP_TERMINAL        MSA_SCHEMA.ORDERS.TERMINAL%TYPE;
        TMP_ORDERTRACE      MSA_SCHEMA.ORDERS.ORDERTRACE%TYPE;
        TMP_RESPONSECODE    MSA_SCHEMA.ORDERS.RESPONSECODE%TYPE;
        TMP_TRANSACTIONTYPE MSA_SCHEMA.ORDERS.TRANSACTIONTYPE%TYPE;
        TMP_CREDIT          MSA_SCHEMA.ORDERS.CREDIT%TYPE;
        TMP_PROVIDER        MSA_SCHEMA.ORDERS.PROVIDER%TYPE;
        TMP_CREATEDATE      MSA_SCHEMA.ORDERS.CREATEDATE%TYPE;
        TMP_ASSIGNEDCREDIT  MSA_SCHEMA.ORDERS.ASSIGNEDCREDIT%TYPE;
        TMP_CASHAMOUNT      MSA_SCHEMA.ORDERS.CASHAMOUNT%TYPE;
        TMP_REQUESTDATE     MSA_SCHEMA.ORDERS.REQUESTDATE%TYPE;

    BEGIN
        V_ERROR_MSG := '';

        IF P_JSON_DATA IS NULL THEN
                    V_ERROR_MSG := 'Error: JSON data is missing.';
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';
        ELSE
            BEGIN
                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            EXCEPTION
                WHEN OTHERS THEN
                    V_ERROR_MSG := 'Error: Invalid JSON data format.';
            END;
            IF V_ERROR_MSG IS NULL THEN
            IF JSON_DATA IS NOT NULL THEN
                V_ORDER_ID := JSON_DATA.GET_NUMBER('orderTrace');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V1_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CREDITAMOUNT := JSON_DATA.GET_NUMBER('creditAmount');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                OPEN V_CURSOR FOR
                    SELECT
                        *
                    FROM
                        MSA_SCHEMA.ORDERS O
                    WHERE
                        O.ORDERTRACE = V_ORDER_ID
                        AND O.RRN = V_RRN
                        AND O.STAN = V_STAN
                        AND O.V_NATIONAL_CODE = V1_NATIONAL_CODE
                        AND O.TERMINAL = V_TERMINAL_NUMBER
                        AND O.TRANSACTIONTYPE='200';
                LOOP
                    FETCH V_CURSOR INTO TMP_RRN, TMP_STAN, TMP_V_NATIONAL_CODE, TMP_CARDNUMBER, TMP_TERMINAL, TMP_ORDERTRACE, TMP_RESPONSECODE, TMP_TRANSACTIONTYPE, TMP_CREDIT, TMP_PROVIDER, TMP_CREATEDATE, TMP_ASSIGNEDCREDIT, TMP_CASHAMOUNT, TMP_REQUESTDATE;
                    EXIT WHEN V_CURSOR%NOTFOUND;

                    INSERT INTO MSA_SCHEMA.ORDERS (
                        ORDERTRACE,
                        RRN,
                        STAN,
                        V_NATIONAL_CODE,
                        CARDNUMBER,
                        TERMINAL,
                        REQUESTDATE,
                        RESPONSECODE,
                        TRANSACTIONTYPE,
                        CREDIT,
                        PROVIDER,
                        CREATEDATE,
                        ASSIGNEDCREDIT,
                        CASHAMOUNT
                    ) VALUES (
                        TMP_ORDERTRACE,
                        TMP_RRN,
                        TMP_STAN,
                        TMP_V_NATIONAL_CODE,
                        TMP_CARDNUMBER,
                        TMP_TERMINAL,
                        TMP_REQUESTDATE,
                        TMP_RESPONSECODE,
                        '220',
                        TMP_CREDIT,
                        TMP_PROVIDER,
                        TMP_CREATEDATE,
                        TMP_ASSIGNEDCREDIT,
                        TMP_CASHAMOUNT
                    );
                END LOOP;
                COMMIT;
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": TRUE/FALSE
                        }
                        }';
            END IF;
            ELSE
               P_RESPONSE := '{"error": "' || V_ERROR_MSG || '"}'; 
            END IF;          
        END IF;
EXCEPTION
    WHEN OTHERS THEN
 -- Set error message for unexpected errors
        V_ERROR_MSG := 'Error: '
                       || SQLERRM;
 -- Return the error message
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}'; 
END CONFIRM_220_CODE_ORDER;


    PROCEDURE REVERSE_420_CODE_ORDER(
        P_JSON_DATA IN VARCHAR2,
        P_RESPONSE OUT VARCHAR2
    ) IS
 -- Procedure to reverse the order distribution and return amounts back to credits
        JSON_DATA           JSON_OBJECT_T;
        V_ORDER_ID          NUMBER;
        V_CHANNEL_TYPE      NUMBER;
        V_RRN               VARCHAR2(50);
        V_STAN              VARCHAR2(50);
        V1_NATIONAL_CODE    VARCHAR2(100);
        V_CARD_NUMBER       VARCHAR2(50);
        V_TERMINAL_NUMBER   VARCHAR2(50);
        V_CREDITAMOUNT      NUMBER;
        V_AMOUNT            NUMBER;
        V_ERROR_MSG         VARCHAR2(200);
        TYPE ORDER_CURSOR_TYPE IS
            REF CURSOR;
        V_CURSOR            ORDER_CURSOR_TYPE;
        TMP_RRN             MSA_SCHEMA.ORDERS.RRN%TYPE;
        TMP_STAN            MSA_SCHEMA.ORDERS.STAN%TYPE;
        TMP_V_NATIONAL_CODE MSA_SCHEMA.ORDERS.V_NATIONAL_CODE%TYPE;
        TMP_CARDNUMBER      MSA_SCHEMA.ORDERS.CARDNUMBER%TYPE;
        TMP_TERMINAL        MSA_SCHEMA.ORDERS.TERMINAL%TYPE;
        TMP_ORDERTRACE      MSA_SCHEMA.ORDERS.ORDERTRACE%TYPE;
        TMP_RESPONSECODE    MSA_SCHEMA.ORDERS.RESPONSECODE%TYPE;
        TMP_TRANSACTIONTYPE MSA_SCHEMA.ORDERS.TRANSACTIONTYPE%TYPE;
        TMP_CREDIT          MSA_SCHEMA.ORDERS.CREDIT%TYPE;
        TMP_PROVIDER        MSA_SCHEMA.ORDERS.PROVIDER%TYPE;
        TMP_CREATEDATE      MSA_SCHEMA.ORDERS.CREATEDATE%TYPE;
        TMP_ASSIGNEDCREDIT  MSA_SCHEMA.ORDERS.ASSIGNEDCREDIT%TYPE;
        TMP_CASHAMOUNT      MSA_SCHEMA.ORDERS.CASHAMOUNT%TYPE;
        TMP_REQUESTDATE     MSA_SCHEMA.ORDERS.REQUESTDATE%TYPE;
    BEGIN
        V_ERROR_MSG := '';

        IF P_JSON_DATA IS NULL THEN
                            V_ERROR_MSG := 'Error: JSON data is missing.';
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}';
        ELSE
            BEGIN
                JSON_DATA := JSON_OBJECT_T(P_JSON_DATA);
            EXCEPTION
                WHEN OTHERS THEN
                    V_ERROR_MSG := 'Error: Invalid JSON data format.';
            END;
            IF V_ERROR_MSG IS NULL THEN
 -- Process JSON data
            IF JSON_DATA IS NOT NULL THEN
                V_ORDER_ID := JSON_DATA.GET_NUMBER('orderTrace');
                V_CHANNEL_TYPE := JSON_DATA.GET_NUMBER('channelType');
                V_RRN := JSON_DATA.GET_STRING('rrn');
                V_STAN := JSON_DATA.GET_STRING('stan');
                V1_NATIONAL_CODE := JSON_DATA.GET_STRING('nationalCode');
                V_CARD_NUMBER := JSON_DATA.GET_STRING('cardNumber');
                V_TERMINAL_NUMBER := JSON_DATA.GET_STRING('terminalNumber');
                V_CREDITAMOUNT := JSON_DATA.GET_NUMBER('creditAmount');
                V_AMOUNT := JSON_DATA.GET_NUMBER('amount');
                OPEN V_CURSOR FOR
                    SELECT
                        *
                    FROM
                        MSA_SCHEMA.ORDERS O
                    WHERE
                        O.ORDERTRACE = V_ORDER_ID
                        AND O.RRN = V_RRN
                        AND O.STAN = V_STAN
                        AND O.V_NATIONAL_CODE = V1_NATIONAL_CODE
                        AND O.TERMINAL = V_TERMINAL_NUMBER
                        AND O.TRANSACTIONTYPE='200';
                LOOP
                    FETCH V_CURSOR INTO TMP_RRN, TMP_STAN, TMP_V_NATIONAL_CODE, TMP_CARDNUMBER, TMP_TERMINAL, TMP_ORDERTRACE, TMP_RESPONSECODE, TMP_TRANSACTIONTYPE, TMP_CREDIT, TMP_PROVIDER, TMP_CREATEDATE, TMP_ASSIGNEDCREDIT, TMP_CASHAMOUNT, TMP_REQUESTDATE;
                    EXIT WHEN V_CURSOR%NOTFOUND;
 -- Check if the record doesn't already exist in MSA_SCHEMA.ORDERS table before inserting
                    INSERT INTO MSA_SCHEMA.ORDERS (
                        ORDERTRACE,
                        RRN,
                        STAN,
                        V_NATIONAL_CODE,
                        CARDNUMBER,
                        TERMINAL,
                        REQUESTDATE,
                        RESPONSECODE,
                        TRANSACTIONTYPE,
                        CREDIT,
                        PROVIDER,
                        CREATEDATE,
                        ASSIGNEDCREDIT,
                        CASHAMOUNT
                    ) VALUES (
                        TMP_ORDERTRACE,
                        TMP_RRN,
                        TMP_STAN,
                        TMP_V_NATIONAL_CODE,
                        TMP_CARDNUMBER,
                        TMP_TERMINAL,
                        TMP_REQUESTDATE,
                        TMP_RESPONSECODE,
                        '420',
                        TMP_CREDIT,
                        TMP_PROVIDER,
                        TMP_CREATEDATE,
                        TMP_ASSIGNEDCREDIT,
                        TMP_CASHAMOUNT
                    );
                END LOOP;

                COMMIT;
                P_RESPONSE := '{
                    "message": "POST request successful.",
                    "isError": false,
                    "statusCode": 200,
                    "result": {
                        "status": true,
                        "responseCode": 0,
                        "data": TRUE/FALSE
                        }
                        }';
            END IF;
            ELSE
               P_RESPONSE := '{"error": "' || V_ERROR_MSG || '"}'; 
        END IF;
        END IF;
 --FETCH order_cur INTO ORDER_RECORD;
        FOR R IN (
SELECT ORDERTRACE, V_NATIONAL_CODE, ASSIGNEDCREDIT, CREDITTYPE FROM
(SELECT
                ROWNUM RN,
                O.ORDERTRACE,
                O.V_NATIONAL_CODE,                
                O.ASSIGNEDCREDIT,
                OT.CREDITTYPE
            FROM
                MSA_SCHEMA.ORDERS O
            INNER JOIN
                MSA_SCHEMA.ITEMORDER OT
            ON O.RRN = OT.RRN
            WHERE
                O.ORDERTRACE = 411
            AND
                O.TRANSACTIONTYPE=200)
                WHERE RN=1
        ) LOOP
            UPDATE MSA_SCHEMA.CREDITS
            SET
                TOTALCREDIT = TOTALCREDIT + R.ASSIGNEDCREDIT
            WHERE
                PARENTNATIONALCODE = R.V_NATIONAL_CODE
                AND CREDITTYPE = R.CREDITTYPE;
            COMMIT;
        END LOOP;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            DBMS_OUTPUT.PUT_LINE('No data found for the given order ID');
        WHEN OTHERS THEN
 -- Set error message for unexpected errors
        V_ERROR_MSG := 'Error: '
                       || SQLERRM;
 -- Return the error message
        P_RESPONSE := '{"error": "'
                      || V_ERROR_MSG
                      || '"}'; 
    END REVERSE_420_CODE_ORDER;
    

END PKG_ORDER_RECEIPT;

CREATE OR REPLACE package "MSA_SCHEMA".PKG_TERMINAL_MGMT is

PROCEDURE ADD_MERCHANT(NAME          IN VARCHAR2,
                         MCODE          IN VARCHAR2,
                         STORENAME     IN VARCHAR2,
                         BUSINESSTITLE IN VARCHAR2,
                         NATIONALCODE  IN VARCHAR2,
                         TAXCODE       IN VARCHAR2,
                         BUSINESSCODE  IN VARCHAR2,
                         PHONE         IN VARCHAR2,
                         PROVINCECODE IN VARCHAR2,
                         CITYCODE IN VARCHAR2,
                         POSTALCODE    IN VARCHAR2,
                         ADDRESS       IN VARCHAR2,
                         MOBILENUMBER IN VARCHAR2,
                         IIN IN VARCHAR2,
                         CODE          IN VARCHAR2,
                         IBAN          IN VARCHAR2,
                         LATITUDE      IN VARCHAR2,
                         LONGITUDE     IN VARCHAR2,
                         SUPPORTMOBILENUMBER IN VARCHAR2,
                         ACTIVE IN VARCHAR2, IS_VALIDATION OUT BOOLEAN);

end PKG_TERMINAL_MGMT;


CREATE OR REPLACE PACKAGE BODY "MSA_SCHEMA".PKG_TERMINAL_MGMT IS

  PROCEDURE ADD_MERCHANT(NAME                IN VARCHAR2,
                         MCODE               IN VARCHAR2,
                         STORENAME           IN VARCHAR2,
                         BUSINESSTITLE       IN VARCHAR2,
                         NATIONALCODE        IN VARCHAR2,
                         TAXCODE             IN VARCHAR2,
                         BUSINESSCODE        IN VARCHAR2,
                         PHONE               IN VARCHAR2,
                         PROVINCECODE        IN VARCHAR2,
                         CITYCODE            IN VARCHAR2,
                         POSTALCODE          IN VARCHAR2,
                         ADDRESS             IN VARCHAR2,
                         MOBILENUMBER        IN VARCHAR2,
                         IIN                 IN VARCHAR2,
                         CODE                IN VARCHAR2,
                         IBAN                IN VARCHAR2,
                         LATITUDE            IN VARCHAR2,
                         LONGITUDE           IN VARCHAR2,
                         SUPPORTMOBILENUMBER IN VARCHAR2,
                         ACTIVE              IN VARCHAR2,
                         IS_VALIDATION       OUT BOOLEAN) IS
    L_PROVIDER            NUMBER(10);
    L_NAME                VARCHAR2(255) := NAME;
    L_MCODE               VARCHAR2(20) := MCODE;
    L_STORENAME           VARCHAR2(255) := STORENAME;
    L_BUSINESSTITLE       VARCHAR2(100) := BUSINESSTITLE;
    L_NATIONALCODE        VARCHAR2(255) := NATIONALCODE;
    L_TAXCODE             VARCHAR2(50) := TAXCODE;
    L_BUSINESSCODE        VARCHAR2(20) := BUSINESSCODE;
    L_ISACTIVE            VARCHAR2(20);
    L_PHONE               VARCHAR2(20) := PHONE;
    L_PROVINCECODE        VARCHAR2(50) := PROVINCECODE;
    L_CITYCODE            VARCHAR2(50) := CITYCODE;
    L_POSTALCODE          VARCHAR2(10) := POSTALCODE;
    L_ADDRESS             VARCHAR2(255) := ADDRESS;
    L_MOBILENUMBER        VARCHAR2(20) := MOBILENUMBER;
    L_ID_MERCHANT         NUMBER(10);
    L_CODE_MERCHANT       VARCHAR2(20);
    L_TERMINALTYPE        NUMBER(10) := 0;
    L_IIN                 VARCHAR2(20) := IIN;
    L_CODE                VARCHAR2(50) := CODE;
    L_IBAN                VARCHAR2(50) := IBAN;
    L_LATITUDE            VARCHAR2(100) := LATITUDE;
    L_LONGITUDE           VARCHAR2(100) := LONGITUDE;
    L_SUPPORTMOBILENUMBER VARCHAR2(20) := SUPPORTMOBILENUMBER;
    L_ISVALID             CHAR(1) := '0';
    L_INCLUDE             NUMBER(10);
  BEGIN
    IF ACTIVE = 'true' THEN
    L_ISACTIVE := '1';
    ELSE
    L_ISACTIVE := '0';
    END IF;
    SELECT ID INTO L_PROVIDER  FROM MSA_AUTH.PROVIDERS
    WHERE CODE=L_IIN;
    SELECT COUNT(*)
      INTO L_INCLUDE
      FROM MSA_SCHEMA.TERMINALS TR
     WHERE TR.CODE = L_CODE
       AND TR.IIN = L_IIN;
    IF L_INCLUDE = 0 THEN
      INSERT INTO MSA_SCHEMA.MERCHANTS
        (PROVIDER,
         NAME,
         CODE,
         STORENAME,
         BUSINESSTITLE,
         NATIONALCODE,
         TAXCODE,
         LOCATION,
         BUSINESSCODE,
         ISACTIVE,
         PHONE,
         POSTALCODE,
         ADDRESS)
      VALUES
        (L_PROVIDER,
         L_NAME,
         L_MCODE,
         L_STORENAME,
         L_BUSINESSTITLE,
         L_NATIONALCODE,
         L_TAXCODE,
         L_CITYCODE,
         L_BUSINESSCODE,
         L_ISACTIVE,
         L_PHONE,
         L_POSTALCODE,
         L_ADDRESS);
      COMMIT;
      SELECT ID, CODE
        INTO L_ID_MERCHANT, L_CODE_MERCHANT
        FROM MSA_SCHEMA.MERCHANTS T
       WHERE NATIONALCODE = L_NATIONALCODE
         and CREATEDATE =
             (select max(CREATEDATE)
                FROM MSA_SCHEMA.MERCHANTS T
               WHERE NATIONALCODE = L_NATIONALCODE);
      INSERT INTO MSA_SCHEMA.TERMINALS T
        (T.TERMINALTYPE,
         T.MERCHANT,
         T.MERCHANTSCODE,
         T.IIN,
         T.CODE,
         T.IBAN,
         T.LATITUDE,
         T.LONGITUDE,
         T.SUPPORTMOBILENUMBER,
         T.ISVALID,
         T.ISACTIVE)
      VALUES
        (L_TERMINALTYPE,
         L_ID_MERCHANT,
         L_CODE_MERCHANT,
         L_IIN,
         L_CODE,
         L_IBAN,
         L_LATITUDE,
         L_LONGITUDE,
         L_SUPPORTMOBILENUMBER,
         L_ISVALID,
         L_ISACTIVE);
      COMMIT;
      IS_VALIDATION := TRUE;
    ELSE 
      IS_VALIDATION := FALSE;
    END IF;
    
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      IS_VALIDATION := FALSE;
  END ADD_MERCHANT;
END PKG_TERMINAL_MGMT;


