#!/usr/bin/env python3
# Designed for use with boofuzz v0.4.1
import sys
from boofuzz import *

def main():

    #variables and lists
    functionCodes = ("Read Device Identification", "Read Discrete Inputs", "Read Input Registers", "Read Multiple Holding Registers", "Write Single Holding Register", "Write Single Coil", "Write Multiple Coils", "Write Multiple Holding Registers", "Read/Write Multiple Registers", "Mask Write Register", "Read File Record", "WriteFileRecord", "Read Exception Status", "Report Slave ID", "Read Device Identification")

    # Checking command arguments and usage
    if len(sys.argv) < 2:
        print("Usage: python3 modbus.py IP Port")
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    #Connect to the Modbus devise
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
        ),
    )

    # Boofuzz initializers ----
    # Read registers ---
    s_initialize("read_coil_memory")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)  
    #Modbus
    s_byte(0x01,name='funcCode read coil memory', fuzzable=False)
    s_bytes(b"\x00\x01", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Word count - amount', fuzzable=True)

    s_initialize("Read Discrete Inputs")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x02,name='Read Discrete Inputs',fuzzable=False)
    s_bytes(b"\x00\x00", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x00", name='Word count - amount - quantity', fuzzable=True)

    s_initialize("Read Input Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x04,name='Read Input Registers',fuzzable=False)
    s_bytes(b"\x00\x00", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x00", name='Word count - amount - quantity', fuzzable=True)

    s_initialize("Read Multiple Holding Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x03,name='Read Multiple Holding Registers',fuzzable=False)
    s_bytes(b"\x00\x01", name='Start address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Word count - amount', fuzzable=True)

    #Write registers
    s_initialize("Write Single Holding Register")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x06,name='Write Single Holding Register',fuzzable=False)
    s_bytes(b"\x00\x01", name='Referance Number - address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Data - value', fuzzable=True)

    s_initialize("Write Single Coil")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x05,name='Write Single Coil',fuzzable=False)
    s_bytes(b"\x00\x01", name='Output address', fuzzable=True)
    s_bytes(b"\x00\x10", name='Output data', fuzzable=True)

    s_initialize("Write Multiple Coils")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x0f,name='Write Multiple Coils',fuzzable=False)
    s_bytes(b"\x00\x00", name='Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Quantety - count', fuzzable=True)
    s_byte(0x00, name='byte count', fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    s_initialize("Write Multiple Holding Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x10,name='Write Multiple Holding Registers',fuzzable=False)
    s_bytes(b"\x00\x00", name='Referance number', fuzzable=True)
    s_bytes(b"\x00\x01", name='Quantety - word count', fuzzable=True)
    s_byte(0x00, name='byte count', fuzzable=True)
    s_byte(0x00, name='register number', fuzzable=True)
    s_string('AA', name='Data for input', fuzzable=True)

    s_initialize("Read/Write Multiple Registers")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
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
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x16,name='Mask Write Register',fuzzable=False)
    s_byte(0x00,name='Ref address',fuzzable=False)
    s_byte(0x00,name='AndMask',fuzzable=False)
    s_byte(0x00,name='OrMask',fuzzable=False)
    s_string('AA', name='Data for input', fuzzable=True)

    #Function code 24 - Read FIFO Queue -TBC

    s_initialize("Read File Record")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x14,name='Read File Record',fuzzable=False)
    s_byte(0x00,name='Byte count',fuzzable=False)

    s_initialize("WriteFileRecord")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x15,name='WriteFileRecord',fuzzable=False)
    s_byte(0x00,name='Byte count',fuzzable=False)
    s_string('AA', name='Data for input', fuzzable=True)

    #Diagnostics functions codes

    s_initialize("Read Exception Status")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x07,name='Read Exception Status',fuzzable=False)

    #Function code 8 - Diagnostic -TBC
    #Function code 11 - Get Com Event Counter -TBC
    #Function code 12 - Get Com Event Log -TBC

    s_initialize("Report Slave ID")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x11,name='Report Slave ID',fuzzable=False)

    s_initialize("Read Device Identification")
    #ModbusTCP
    s_bytes(b"\x00\x01", name='Trans ID', fuzzable=True)
    s_bytes(b"\x00\x00", name='Protocol ID', fuzzable=False) #0 for modbusTCP
    s_bytes(b"\x00\x06", name='Length', fuzzable=True)
    s_byte(0xff,name='unit Identifier',fuzzable=True)    
    #Modbus
    s_byte(0x2b,name='Read Device Identification',fuzzable=False)
    s_byte(0x00, name='MAI Type', fuzzable=True)
    s_byte(0x00, name='Read Device Id', fuzzable=True)
    s_byte(0x00, name='Object vendor name', fuzzable=True)

    for code in functionCodes:
        session.connect(s_get(code))
    
    session.fuzz()


if __name__ == "__main__":
    main()
