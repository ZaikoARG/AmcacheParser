# **AmcacheParser**

<p align="center">
    <a href="https://github.com/ZaikoARG/PyDump/blob/main/LICENSE">
        <img src="https://img.shields.io/badge/license-GPL%203.0-blue.svg" />
    </a>
    <a href="https://www.python.org/">
    	<img src="https://img.shields.io/badge/built%20with-Python%203-red.svg" />
    </a>
</p>

---

**Discord:** ZaikoARG#1187

---

AmcacheParser is a Windows forensic tool made purely in Python to parse Amcache.hve file. This tool includes:
* Parser with output in JSON of Hive files (Not only Amcache).
* Handler of live files (Used by another process).
* Filter by Key/Keys (Returns only the specified Keys).
* Authomatic live system Amcache.hve file parser
* Velocity

## Usage

Parse Live System Amcache.hve File.

`python amcacheparser.py -l -o amc.json`

Parse Specific Hive File.

`python amcacheparser.py -f C:\Users\ZaikoARG\hive_file.hve -o amc.json`

Parse and Filter only for a one key.

`python amcacheparser.py -l -k InventoryApplicationFile -o amc.json`

Parse and Filter for multiple keys.

`python amcacheparser.py -l -k InventoryApplicationFile,DeviceCensus -o amc.json`

## Documentation
|Option|Description|
|--|--|
|-f, --file [file_path]|Path of the Amcache.hve file (or other Hive File)|
|-l, --live-amcache [process_name]|Parse the Live Amcache.hve file of your system.|
|-o, --output [file]|Output JSON file path.|
|-k, --key [key] or [key,key]|Return only the content of the specified key (search for multiple keys by separating them with a comma)|

## Copyright Statement

To handle the live system hive files I used code created by Maxim Suhanov, under the GPL 3.0 license. All rights reserved.

Font: https://github.com/msuhanov/yarp/blob/master/yarp/RegistryLive.py

## License
Copyright © 2022, ZaikoARG. All rights reserved.

This project is made available under the terms of the GNU GPL, version 3.

See the [License](https://github.com/ZaikoARG/AmcacheParser/blob/main/LICENSE) file.