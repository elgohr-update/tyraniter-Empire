# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] - 2019-03-01

### Added

* **tgssub** action
    * Substitutes in alternate sname (cifs) or SPN (ldap/computer.domain.com) into an existing service ticket


## [1.4.1] - 2019-02-25

### Added
* to **asktgs** action
    * /enctype:[RC4/AES128/AES256/DES] now forces that particular encryption type in the TGS-REQ

### Changed
* **asktgt** action
    * Returned tickets now run through the **describe** command
* **describe** action
    * Kerberoast hash now only extracted from RC4_HMAC tickets


## [1.4.0] - 2019-02-16

### Added
* **hash** action
    * hashes a given password to rc4_hmac form, and if /user and /domain supplied, calculates aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5 forms 

### Changed
* **kerberoast** action
    * Fixed query that checks that rc4_hmac is flipped in msds-supportedencryption types, because "lol Microsoft"
* **asktgt** action
    * /aes128 and /aes now supported for **/enctype** when used with **/password**
* **crypto** 
    * Replaced @qlemaire's PR of Kevin-Robertson' Get-KerberosAESKey hash code with @gentilkiwi's KERB_ECRYPT HashPassword approach
* **README**
    * added @elad_shamir into the references


## [1.3.6] - 2019-02-14

### Added
* **kerberoast** action
    * /rc4opsec option to use **tgtdeleg** and filter out AES-enabled accounts
    * /aes option to AES roast only AES-enabled accounts

### Changed
* **kerberoast** action
    * Default user query searches for accounts with RC4 enabled
    * Default behavior when using the /tgtdeleg flag requests RC4 for ALL accounts (including AES)
    * Display "Supported ETypes" in enumerated output
* **tgtdeleg** action
    * Changed the default requested SPN from HOST/dc.domain.com to cifs/dc.domain.com

### Fixed
* Kerberoast hash display for some option combinations


## [1.3.5] - 2019-02-13

### Changed
* **kerberoast** action
    * now has /ticket option to use an existing TGT for Kerberoasting
    * now has /usetgtdeleg option to use **tgtdeleg** option as the TGT for Kerberoasting
    * LDAP user search path and number of found users now output
* **describe** action
    * Kerberoast hash output now generated for service tickets

### Fixed
* Kerberoast hash display but when /spn and /outfile were specified
* Kerberoast samaccountname now properly put into hash output


## [1.3.4] - 2019-02-12

### Changed
* **kerberoast** action now has /domain and /dc like **asreproast** action
* **kerberoast** and **asreproast** now properly work over domain trusts
* **triage** command now works for the current non-elevated user, outputting current LUID as well
* Current LUID output also added for non-elevated **dump** and **klist** commands
* Added Opsec section in README.md


## [1.3.3] - 2019-02-11
### Changed
* Landed @leechristensen's cleanup of the Monitor4624 code
* Restructed the README.md to match the help output, updated all examples, added table of contents


## [1.3.3] - 2019-02-07
### Added
* **triage** action
    * Quickly triages the users and present tickets on a machine

### Changed
* **dump** and **klist** changed default LUID output to hex format


## [1.3.2] - 2019-02-06
### Added
* **kerberoast** and **asreproast** actions
    * Added /outfile:X to output hashes to a file, one hash per line

### Changed
* **asreproast** changed asreproast's default behavior to match **kerberoast**
* Clustered the default output help menu around function (things were getting crowded)


## [1.3.1] - 2019-02-06
### Fixed
* Changed underlying LUID logic to handle UInt64s


## [1.3.0] - 2019-02-05
### Added
* **klist** action
    * lists current user's (or if elevated, all users') ticket information

### Changed
* **s4u** landed @eladshamir's pull requests
    * RBCD support
    * support loading TGS from Kirbi to skip S4U2Self and perform S4U2Proxy only
    * perform S4U2Self only
    * print output for each stage
* **asreproast** landed @rvrsh3ll's pull request
    * added hashcat output format
* **asktgt** landed @qlemaire's pull request
    * now accepts a /password:X parameter
* **monitor** and **harvest** landed @djhohnstein's pull request
    * ticket extraction can now be saved to the registry with the "/registry:X" flag

### Fixed
* **dump** display of service tickets with multiple slashes
* response buffer size in lib/Networking.cs increased for large ticket responses
* landed @BlueSkeye's fixes for PTT bug fix, TicketFlags display, and dead code removal in PA_DATA.Encode


## [1.2.1] - 2018-10-09
### Changed
* Merged @mark-s' PR that broke out Program.cs' commands into 'Command' classes for easier command addition.
* Commands that pass /dc:X are now passed through Networking.GetDCIP(), which resolves the DC name (if null) and returns the DC IP. Code refactored to use this centralized resolver.
* The /user:USER flag can now be /user:DOMAIN.COM\USER (auto-completes /domain:Y).
* The **harvest** command now returns the user ticket with the latest renew_till time on intial extraction.


## [1.2.0] - 2018-10-03
### Added
* **changepw** action
    * implements the AoratoPw user password reset from a TGT .kirbi
    * equivalent to Kekeo's misc::changepw function


## [1.1.0] - 2018-09-31
### Added
* **asktgs** action - takes /ptt:X, /dc:X, /ticket:X flags like asktgt, /service:X takes one or more SPN specifications
* **tgtdeleg** action - reimplements @gentilkiwi's Kekeo tgt::deleg function
    * uses the GSS-API Kerberos specification (RFC 4121) to request a "fake" delegation context that stores a KRB-CRED in the Authenticator Checksum. Combined with extracting the service session key from the local cache, this allows us to recover usable TGTs for the current user without elevation.
* Added CHANGELOG.md

### Changed
* **s4u** action now accepts multiple alternate snames (/altservice:X,Y,...)
    * This executes the S4U2self/S4U2proxy process only once, and substitutes the multiple alternate service names
        into the final resulting service ticket structure(s) for as many snames as specified
* **asreproast** action
    * added eventual hashcat output format, use "/format:<john/hashcat>" (default of "john")

### Fixed
* **dump** action now correctly extracts ServiceName/TargetName strings
* **asreproast** action - fixed salt demarcation line for "asreproast" hashes
* **kerberoast** action
    * Added reference for @machsosec for the KerberosRequestorSecurityToken.GetRequest Kerberoasting Method()
    * Corrected encType extraction for the hash output


## [1.0.0] - 2018-08-24

* Initial release
