from django.shortcuts import render
from django.db import connection
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import oracledb
import json
from sqlalchemy import create_engine
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

#Create your views here.

class LoginView(APIView):
    def post(self, request):
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            conn = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
            cursor = conn.cursor()
            result = cursor.callfunc("MSA_SCHEMA.pkg_auth.login", oracledb.STRING, [username, password])
            result_parts = result.split("-*-")
            id = int(result_parts[1].split(":")[1])
            firstname = result_parts[2].split(":")[1]
            lastname = result_parts[3].split(":")[1]
            jwt_token = result_parts[0].split(":")[1]
            is_active = True if result_parts[4].split(":")[1] == "1" else False
            response_data = {
                "id": id,
                "firstname": firstname,
                "lastname": lastname,
                "username": username,  # Assuming the username is the same as the firstname and lastname
                "jwtToken": jwt_token,
                "isActive": is_active
            }
            response = {
                "message": "POST Request successful.",
                "isError": False,
                "statusCode": 200,
                "result": {
                    "status": True,
                    "responseCode": 0,
                    "data": response_data
                }
            }
            #validation = True  # Assume validation is true for new token
            # if result is not None:
            #     validation_param = cursor.var(bool)
            #     cursor.callproc("MSA_SCHEMA.pkg_auth.VALIDATE_TOKEN", [result, validation_param])
            #     validation = validation_param.values[0]
            cursor.close()
            conn.close()
            return Response(response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ValidationToken(APIView):
    def post(self, request):
        try:
            token = request.data.get("token")
            # print('token:>>> {}'.format(token))
            conn = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
            # print("connection ok.")
            cursor = conn.cursor()
            # print("cursor is ok.")
            validation = True
            validation_param = cursor.var(bool)
            cursor.callproc("MSA_SCHEMA.pkg_auth.VALIDATE_TOKEN", [token, validation_param])
            # print('validation_param ok.')
            # Assume validation is true for new token
            validation = validation_param.values[0]
            cursor.close()
            conn.close()
            return Response({'validation': validation}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class OTPView(APIView):
    def post(self, request):
        try:
            #operator_id  = request.data.get('operator_id')
            mobileNumber = request.data.get('mobileNumber')
            nationalCode = request.data.get('nationalCode')
            # print('mobileNumber is {} and nationalCode is {}'.format(mobileNumber, nationalCode))
            conn = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
            # print("connection ok.")
            cursor = conn.cursor()
            # print("cursor is ok.")
            result = cursor.callfunc("MSA_SCHEMA.pkg_auth.GENERATE_OTP", oracledb.STRING, [mobileNumber, nationalCode])
            # print(result)
            result_parts = result.split("-*-")
            # print(result_parts[0])
            otp_main = result_parts[0].split(":")[1]
            otp_second = result_parts[1].split(":")[1]
            currentChannelTypeID = int(result_parts[2].split(":")[1])
            description = 'user with Nationalcode {}, your code is {}'.format(nationalCode, otp_main)
            response_data = {
                "otp_main": otp_main,
                "otp_second": otp_second,
                "description": description,
                "currentChannelTypeID": currentChannelTypeID,  # Assuming the username is the same as the firstname and lastname
            }            
            response = {
                "message": "POST Request successful.",
                "isError": False,
                "statusCode": 200,
                "result": {
                    "status": True,
                    "responseCode": 0,
                    "data": response_data
                }
            }
            # print('result is ok')
            # print('OTP is {}'.format(result))
            cursor.close()
            conn.close()
            return Response(response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ValidationOTP(APIView):
    def post(self, request):
        try:
            operator_id = request.data.get('operator_id')
            otp = request.data.get('otp')
            # print('operator_id>>>>>>>{} and otp is >>>>>>{}'.format(operator_id, otp) )
            conn  = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
            # print('connect is ok.')
            cursor = conn.cursor()
            # print('cursor is ok.')
            validation = True
            validation_param = cursor.var(bool)
            cursor.callproc("MSA_SCHEMA.pkg_auth.VALIDATE_OTP", [operator_id, otp, validation_param])
            # print('validation is ok.')
            validation = validation_param.values[0]
            cursor.close()
            conn.close()
            return Response({'validation':validation}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DefineTerminal(APIView):
    def post(self, request):
        try:
            terminalNumber = request.data.get('terminalNumber')
            shebaCode = request.data.get('shebaCode')
            iin = request.data.get('iin')
            active = request.data.get('active')
            provincecode = request.data.get('provincecode')
            citycode = request.data.get('citycode')
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            address = request.data.get('address')
            postalCode = request.data.get('postalCode')
            phoneNumber = request.data.get('phoneNumber')
            TaxCode = request.data.get('TaxCode')
            businessCode = request.data.get('businessCode')
            businessTitle = request.data.get('businessTitle')
            storeName = request.data.get('storeName')
            merchantNumber = request.data.get('merchantNumber')
            merchantName = request.data.get('merchantName')
            nationalCode = request.data.get('nationalCode')
            merchantMobileNumber = request.data.get('merchantMobileNumber')
            mobileNumber = request.data.get('mobileNumber')
            procincecode = request.data.get('provincecode')
            citycode = request.data.get('citycode')
            conn  = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
            cursor = conn.cursor()
            validation = True
            validation_param = cursor.var(bool)
            cursor.callproc("MSA_SCHEMA.PKG_TERMINAL_MGMT.ADD_MERCHANT", [merchantName, merchantNumber,storeName,businessTitle,nationalCode,TaxCode, 
                                                                          businessCode,merchantMobileNumber,
                                                                          phoneNumber,citycode,postalCode, address, 
                                                                          procincecode, iin, terminalNumber, shebaCode, latitude,  longitude, mobileNumber,   
                                                                          active[:20], validation_param])
            validation = validation_param.values[0]
            
            cursor.close()
            conn.close()
            print('validation:',validation)

            if validation:
                response = {
                    "message": "success",
                    "isError": False,
                    "responseCode": "00",
                    "data": "define terminal done."
                    }
            else:
                response = {
                    "message": "error",
                    "isError": True,
                    "responseCode": "58",
                    "data": "define terminal process failed."
                    }
            return Response(response, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class GetItemOrder(APIView):
    def post(self, request):
        json_data = request.data
        json_str = json.dumps(json_data)
        print(json_str)       
     
        connection = oracledb.connect(user="msa_schema", password="msa_schema", host='10.2.10.20', port=1521, service_name='dbdev')
        cursor = connection.cursor()
        
        try:
            # Call Oracle procedure to process JSON data
            cursor.callproc("MSA_SCHEMA.PKG_ORDER.PROCESS_JSON_DATA", [json_str])
            connection.commit()
            
        except oracledb.DatabaseError as e:
            error, = e.args
            return Response({"error_message": str(error)})
        finally:
            cursor.close()
            connection.close()
            response = {
"message": "POST request successful.",
"isError": False, 
"statusCode": 200,
"result": {
"status": True,
"responseCode":0,
"data":{
"rrn": "123456789012",
"stan": "123456",
"orderTrace": "1234567890123",
"terminalNumber": "12345678",
"creditAmount": 70000,
"amount": 100000,
"assignedCredits": [{
"commodityCode": "5",
"commodityName":"ماکارونی",
"unitCode": "01",
"unitName" : "گرم",
"assigedCredit": 2000,
"currentCredit": 5000
}]
}
}
}
        
        return Response({"message": "JSON data processed successfully"})