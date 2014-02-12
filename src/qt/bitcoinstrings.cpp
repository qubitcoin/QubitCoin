#include <QtGlobal>
// Automatically generated by extract_strings.py
#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif
static const char UNUSED *bitcoin_strings[] = {
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"%s, you must set a rpcpassword in the configuration file:\n"
"%s\n"
"It is recommended you use the following random password:\n"
"rpcuser=Qubitrpc\n"
"rpcpassword=%s\n"
"(you do not need to remember this password)\n"
"The username and password MUST NOT be the same.\n"
"If the file does not exist, create it with owner-readable-only file "
"permissions.\n"
"It is also recommended to set alertnotify so you are notified of problems;\n"
"for example: alertnotify=echo %%s | mail -s \"QubitCoin Alert\" admin@foo.com\n"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:"
"@STRENGTH)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"An error occurred while setting up the RPC port %u for listening on IPv4: %s"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"An error occurred while setting up the RPC port %u for listening on IPv6, "
"falling back to IPv4: %s"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Bind to given address and always listen on it. Use [host]:port notation for "
"IPv6"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Cannot obtain a lock on data directory %s. QubitCoin is probably already "
"running."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Error: The transaction was rejected! This might happen if some of the coins "
"in your wallet were already spent, such as if you used a copy of wallet.dat "
"and coins were spent in the copy but not marked as spent here."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Error: This transaction requires a transaction fee of at least %s because of "
"its amount, complexity, or use of recently received funds!"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Execute command when a relevant alert is received (%s in cmd is replaced by "
"message)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Execute command when a wallet transaction changes (%s in cmd is replaced by "
"TxID)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Execute command when the best block changes (%s in cmd is replaced by block "
"hash)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Listen for JSON-RPC connections on <port> (default: 8372 or testnet: 18372)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Number of seconds to keep misbehaving peers from reconnecting (default: "
"86400)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Set maximum size of high-priority/low-fee transactions in bytes (default: "
"27000)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Set the number of script verification threads (up to 16, 0 = auto, <0 = "
"leave that many cores free, default: 0)"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"This is a pre-release test build - use at your own risk - do not use for "
"mining or merchant applications"),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Unable to bind to %s on this computer. QubitCoin is probably already running."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Warning: -paytxfee is set very high! This is the transaction fee you will "
"pay if you send a transaction."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Warning: Displayed transactions may not be correct! You may need to upgrade, "
"or other nodes may need to upgrade."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Warning: Please check that your computer's date and time are correct! If "
"your clock is wrong QubitCoin will not work properly."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Warning: error reading wallet.dat! All keys read correctly, but transaction "
"data or address book entries might be missing or incorrect."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"Warning: wallet.dat corrupt, data salvaged! Original wallet.dat saved as "
"wallet.{timestamp}.bak in %s; if your balance or transactions are incorrect "
"you should restore from a backup."),
QT_TRANSLATE_NOOP("QubitCoin-core", ""
"You must set rpcpassword=<password> in the configuration file:\n"
"%s\n"
"If the file does not exist, create it with owner-readable-only file "
"permissions."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Accept command line and JSON-RPC commands"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Accept connections from outside (default: 1 if no -proxy or -connect)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Add a node to connect to and attempt to keep the connection open"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Allow DNS lookups for -addnode, -seednode and -connect"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Allow JSON-RPC connections from specified IP address"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Attempt to recover private keys from a corrupt wallet.dat"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Qubit version"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Block creation options:"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Cannot downgrade wallet"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Cannot resolve -bind address: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Cannot resolve -externalip address: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Cannot write default address"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Connect only to the specified node(s)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Connect through socks proxy"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Connect to a node to retrieve peer addresses, and disconnect"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Corrupted block database detected"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Discover own IP address (default: 1 when listening and no -externalip)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Do you want to rebuild the block database now?"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Done loading"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error initializing block database"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error initializing wallet database environment %s!"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error loading block database"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error loading wallet.dat"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error loading wallet.dat: Wallet corrupted"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error loading wallet.dat: Wallet requires newer version of Qubit"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error opening block database"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error: Disk space is low!"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error: Wallet locked, unable to create transaction!"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Error: system error: "),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to listen on any port. Use -listen=0 if you want this."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to read block info"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to read block"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to sync block index"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write block index"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write block info"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write block"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write file info"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write to coin database"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write transaction index"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Failed to write undo data"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Fee per KB to add to transactions you send"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Find peers using DNS lookup (default: 1 unless -connect)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Generate coins (default: 0)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Get help for a command"),
QT_TRANSLATE_NOOP("QubitCoin-core", "How many blocks to check at startup (default: 288, 0 = all)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "How thorough the block verification is (0-4, default: 3)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Imports blocks from external blk000??.dat file"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Information"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Insufficient funds"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid -proxy address: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid -tor address: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid amount for -minrelaytxfee=<amount>: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid amount for -mintxfee=<amount>: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid amount for -paytxfee=<amount>: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Invalid amount"),
QT_TRANSLATE_NOOP("QubitCoin-core", "List commands"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Listen for connections on <port> (default: 8373 or testnet: 18373)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Loading addresses..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Loading block index..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Loading wallet..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Maintain a full transaction index (default: 0)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Maintain at most <n> connections to peers (default: 125)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Not enough file descriptors available."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Only accept block chain matching built-in checkpoints (default: 1)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Only connect to nodes in network <net> (IPv4, IPv6 or Tor)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Options:"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Output extra debugging information. Implies all other -debug* options"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Output extra network debugging information"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Password for JSON-RPC connections"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Prepend debug output with timestamp"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Rebuild block chain index from current blk000??.dat files"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Rescan the block chain for missing wallet transactions"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Rescanning..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Run in the background as a daemon and accept commands"),
QT_TRANSLATE_NOOP("QubitCoin-core", "SSL options: (see the QubitCoin Wiki for SSL setup instructions)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Select the version of socks proxy to use (4-5, default: 5)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Send command to -server or QubitCoind"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Send commands to node running on <ip> (default: 127.0.0.1)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Send trace/debug info to console instead of debug.log file"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Send trace/debug info to debugger"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Server certificate file (default: server.cert)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Server private key (default: server.pem)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Set database cache size in megabytes (default: 25)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Set key pool size to <n> (default: 100)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Set maximum block size in bytes (default: 250000)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Set minimum block size in bytes (default: 0)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Set the number of threads to service RPC calls (default: 4)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Shrink debug.log file on client startup (default: 1 when no -debug)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Signing transaction failed"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Specify configuration file (default: QubitCoin.conf)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Specify connection timeout in milliseconds (default: 5000)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Specify data directory"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Specify pid file (default: QubitCoind.pid)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Specify your own public address"),
QT_TRANSLATE_NOOP("QubitCoin-core", "System error: "),
QT_TRANSLATE_NOOP("QubitCoin-core", "This help message"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Threshold for disconnecting misbehaving peers (default: 100)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "To use the %s option"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Transaction amount too small"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Transaction amounts must be positive"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Transaction too large"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Unable to bind to %s on this computer (bind returned error %d, %s)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Unknown -socks proxy version requested: %i"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Unknown network specified in -onlynet: '%s'"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Upgrade wallet to latest format"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Usage:"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Use OpenSSL (https) for JSON-RPC connections"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Use UPnP to map the listening port (default: 0)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Use UPnP to map the listening port (default: 1 when listening)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Use proxy to reach tor hidden services (default: same as -proxy)"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Use the test network"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Username for JSON-RPC connections"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Verifying blocks..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Verifying wallet..."),
QT_TRANSLATE_NOOP("QubitCoin-core", "Wallet needed to be rewritten: restart QubitCoin to complete"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Warning"),
QT_TRANSLATE_NOOP("QubitCoin-core", "Warning: This version is obsolete, upgrade required!"),
QT_TRANSLATE_NOOP("QubitCoin-core", "You need to rebuild the databases using -reindex to change -txindex"),
QT_TRANSLATE_NOOP("QubitCoin-core", "wallet.dat corrupt, salvage failed"),
};
