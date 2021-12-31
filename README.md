# Window Task Scheduler Action Executables Tested Against VirusTotal

- By Stephen Genusa [http://www.github.com/stephengenusa](http://www.github.com/stephengenusa)
- December 31, 2021
- Built using Python 3.9

This program attempts to determine _all_ the executables located in Windows Task Scheduler's actions -- 
not just the primary executable but it also attempts to find executables like DLLs passed as parameters. 
Once the list is built, each SHA-256 hash is tested against VirusTotal and analysis results are 
reported. If the binary hasn't been seen before by VT, the binary is submitted for analysis.

You'll need a VT API key and store it in the environment variable VIRUSTOTAL_API_KEY

