#!/usr/bin/env python3
# Designed for use with boofuzz v0.4.1
# Author : Soren Egede Knudsen - Egede ApS
#Verion 0.2.1 - under development
import sys
from boofuzz import *


def main():

    #variables and lists
    menuactive = True
    menuAnswer = 0
    functionCodesToFuzz = []
    functionCodesAll = ["Base", "Read Device Identification", "Read Discrete Inputs", "Read Input Registers", "Read Multiple Holding Registers", "Write Single Holding Register", "Write Single Coil", "Write Multiple Coils", "Write Multiple Holding Registers", "Read/Write Multiple Registers", "Mask Write Register", "Read File Record", "Write File Record", "Read Exception Status", "Report Slave ID"]
    functionCodeReadDeviceIdentification = ["Read Device Identification"]
    functionCodesReadDiscreteInputs = ["Read Discrete Inputs"]
    functioncodeReadInputRegisters = ["Read Input Registers"]
    functioncodeReadMultipleHoldingRegisters = ["Read Multiple Holding Registers"]
    functioncodeWriteSingleHoldingRegister = ["Write Single Holding Register"]
    functioncodeWriteSingleCoil = ["Write Single Coil"]
    functioncodeWriteMultipleCoils = ["Write Multiple Coils"]
    functioncodeWriteMultipleHoldingRegisters = ["Write Multiple Holding Registers"]
    functioncodeRead_WriteMultipleRegisters = ["Read/Write Multiple Registers"]
    functioncodeMaskWriteRegister = ["Mask Write Register"]
    functioncodeReadFileRecord = ["Read File Record"]
    functioncodeWriteFileRecord = ["Write File Record"]
    functioncodeReadExceptionStatus = ["Read Exception Status"]
    functioncodeReportSlaveID = ["Report Slave ID"]
    functioncodeReadCoilMemory = ["Read Coil Memory"]
    functioncodeBase = ["Base"] 

    #verbose logging information
    csv_log = open('fuzz_results.csv', 'wb') ## create a csv file
    my_logger = [FuzzLoggerCsv(file_handle=csv_log)] ### create a FuzzLoggerCSV object with the file handle of our csv file


    # Checking command arguments and usage
    if len(sys.argv) < 2:
        print("Usage: python3 modbus.py IP Port")
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    #Menu selction of what to fuzz
    while menuactive:
        print("""
        --------------------------------------
        Created by Soren Egede Knudsen @Egede
        --------------------------------------
        What do you want to fuzz?
        1.  Fuzz all function codes and base
        2.  Fuzz Read Device Identification
        3.  Fuzz Read Discrete Inputs
        4.  Fuzz Read Input Registers
        5.  Fuzz Read Multiple Holding Registers
        6.  Fuzz Write Single Holding Register
        7.  Fuzz Write Single Coil
        8.  Fuzz Write Multiple Coils
        9.  Fuzz Write Multiple Holding Registers
        10. Fuzz Read/Write Multiple Registers
        11. Fuzz Mask Write Register
        12. Fuzz Read File Record
        13. Fuzz Write File Record
        14. Fuzz Read Exception Status
        15. Fuzz Report Slave ID
        16. Fuzz Read Coil Memory
        20. Fuzz ModbusTCP - Base protocol
        0. Exit
        """)
        menuAnswer = input("\nSelect an option: ")
        if int(menuAnswer) == 1:
            print("\n All are seleted!!")
            functionCodesToFuzz = functionCodesAll
            break
        elif int(menuAnswer) == 2:
            functionCodesToFuzz = functionCodeReadDeviceIdentification
            break
        elif int(menuAnswer) == 3:
            functionCodesToFuzz = functionCodesReadDiscreteInputs
            break
        elif int(menuAnswer) == 4:
            functionCodesToFuzz = functioncodeReadInputRegisters
            break
        elif int(menuAnswer) == 5:
            functionCodesToFuzz = functioncodeReadMultipleHoldingRegisters
            break
        elif int(menuAnswer) == 6:
            functionCodesToFuzz = functioncodeWriteSingleHoldingRegister 
            break
        elif int(menuAnswer) == 7:
            functionCodesToFuzz = functioncodeWriteSingleCoil
            break
        elif int(menuAnswer) == 8:
            functionCodesToFuzz = functioncodeWriteMultipleCoils
            break     
        elif int(menuAnswer) == 9:
            functionCodesToFuzz = functioncodeWriteMultipleHoldingRegisters
            break 
        elif int(menuAnswer) == 10:
            functionCodesToFuzz = functioncodeRead_WriteMultipleRegisters
            break 
        elif int(menuAnswer) == 11:
            functionCodesToFuzz = functioncodeMaskWriteRegister
            break 
        elif int(menuAnswer) == 12:
            functionCodesToFuzz = functioncodeReadFileRecord
            break 
        elif int(menuAnswer) == 13:
            functionCodesToFuzz = functioncodeWriteFileRecord
            break         
        elif int(menuAnswer) == 14:
            functionCodesToFuzz = functioncodeReadExceptionStatus
            break
        elif int(menuAnswer) == 15:
            functionCodesToFuzz = functioncodeReportSlaveID
            break  
        elif int(menuAnswer) == 16:
            functionCodesToFuzz = functioncodeReadCoilMemory
            break      
        elif int(menuAnswer) == 20:
            functionCodesToFuzz = functioncodeBase
            break       
        elif int(menuAnswer) == 0:
            print("\n Exiting the modbus fuzzer!")
            exit(0)
        else:
            print("\n Wrong selection try again")
        

    #Connect to the Modbus devise
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port)),fuzz_loggers=my_logger) ## set my_logger (csv) as the logger for the session
    

    #session = Session(target=Target(SocketConnection(host, int(port))), post_test_case_callbacks=[target_alive])

    # Boofuzz initializers ----
    # base fuzzing ModbusTCP
    s_initialize("Base")
    #ModbusTCP
    s_byte(0x00, name='Trans ID part one', fuzzable=False) #part one is staticx½
    s_byte(0x01, name='Trans ID part two', fuzzable=True) # part two chenges in two lines to minimise fuzzing 
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_byte(0x00, name='Length part one', fuzzable=False) #part one is static
    s_byte(0x06, name='Length part two', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)  #0xff = server/manster
    #Modbus
    s_byte(0x01,name='funcCode read coil memory', fuzzable=False)
    s_bytes(b"\x00\x01", name='Start address', fuzzable=False)
    s_bytes(b"\x00\x10", name='Word count - amount', fuzzable=False)


    # Read registers ---
    s_initialize("Read Coil Memory")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)  #0xff = server/manster 0x01 = client
    #Modbus
    s_byte(0x01,name='funcCode read coil memory', fuzzable=False)
    s_bytes(b"\x00\x01", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Word count - amount', fuzzable=True)

    s_initialize("Read Discrete Inputs")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x02,name='Read Discrete Inputs',fuzzable=False)
    s_bytes(b"\x00\x00", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x00", name='Word count - amount - quantity', fuzzable=True)

    s_initialize("Read Input Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x04,name='Read Input Registers',fuzzable=False)
    s_bytes(b"\x00\x00", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x00", name='Word count - amount - quantity', fuzzable=True)

    s_initialize("Read Multiple Holding Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x03,name='Read Multiple Holding Registers',fuzzable=False)
    s_bytes(b"\x00\x01", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Word count - amount', fuzzable=True)

    #Write registers
    s_initialize("Write Single Holding Register")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x06,name='Write Single Holding Register',fuzzable=False)
    s_bytes(b"\x00\x01", name='Referance Number - address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Data - value', fuzzable=True)

    s_initialize("Write Single Coil")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x05,name='Write Single Coil',fuzzable=False)
    s_bytes(b"\x00\x01", name='Output address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Output data', fuzzable=True)

    s_initialize("Write Multiple Coils")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x0f,name='Write Multiple Coils',fuzzable=False)
    s_bytes(b"\x00\x00", name='Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Quantety - count', fuzzable=True)
    s_byte(0x00, name='byte count', fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    s_initialize("Write Multiple Holding Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x10,name='Write Multiple Holding Registers',fuzzable=False)
    s_bytes(b"\x00\x00", name='Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Quantety - word count', fuzzable=True)
    s_byte(0x00, name='byte count', fuzzable=True)
    s_byte(0x00, name='register number', fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    s_initialize("Read/Write Multiple Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x17,name='Read/Write Multiple Registers',fuzzable=False)
    s_bytes(b"\x00\x00", name='Read Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Read Quantety - word count', fuzzable=True)
    s_bytes(b"\x00\x00", name='Write Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Write Quantety - word count', fuzzable=True)
    s_byte(0x00, name='byte count', fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    s_initialize("Mask Write Register")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x16,name='Mask Write Register',fuzzable=False)
    s_byte(0x00,name='Ref address',fuzzable=False)
    s_byte(0x00,name='AndMask',fuzzable=False)
    s_byte(0x00,name='OrMask',fuzzable=False)
    s_string('AA', name='Data for input', fuzzable=True)

    #Function code 24 - Read FIFO Queue -TBC

    s_initialize("Read File Record")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x14,name='Read File Record',fuzzable=False)
    s_byte(0x00,name='Byte count',fuzzable=True)

    s_initialize("Write File Record")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x15,name='WriteFileRecord',fuzzable=False)
    s_byte(0x00,name='Byte count',fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    #Diagnostics functions codes

    s_initialize("Read Exception Status")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x07,name='Read Exception Status',fuzzable=False)

    #Function code 8 - Diagnostic -TBC
    #Function code 11 - Get Com Event Counter -TBC
    #Function code 12 - Get Com Event Log -TBC

    s_initialize("Report Slave ID")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x11,name='Report Slave ID',fuzzable=False)

    s_initialize("Read Device Identification")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=False)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=False)
    s_byte(0xff,name='unit Identifier',fuzzable=False)    
    #Modbus
    s_byte(0x2b,name='Read Device Identification',fuzzable=False)
    s_byte(0x00, name='MAI Type', fuzzable=True)
    s_byte(0x00, name='Read Device Id', fuzzable=True)
    s_byte(0x00, name='Object vendor name', fuzzable=True)

    
    for code in functionCodesToFuzz:
        session.connect(s_get(code))
           
    session.fuzz()


if __name__ == "__main__":
    main()
