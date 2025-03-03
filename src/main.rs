use std::collections::{HashMap, HashSet};
use ssh2::Session;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use regex::Regex;
use std::error::Error;
use std::path::Path;
use std::fs;
use std::time::Duration;

/// SSH configuration for a host
#[derive(Debug)]
struct SshHostConfig {
    hostname: String,
    username: String,
    port: u16,
}

/// Server configuration with hostname and log path
struct ServerConfig {
    host: String,
    log_path: String,
}

/// Structure to hold hash information
#[derive(Debug, Clone)]
struct HashInfo {
    period: u64,
    thread: u64,
    hash: String,
}

/// Read the SSH configuration from the default location (~/.ssh/config)
fn read_ssh_config() -> Result<HashMap<String, SshHostConfig>, Box<dyn Error>> {
    let ssh_config_path = dirs::home_dir()
        .ok_or("Could not find home directory")?
        .join(".ssh/config");
    
    if !ssh_config_path.exists() {
        return Err("SSH configuration file not found".into());
    }
    
    let content = fs::read_to_string(ssh_config_path)?;
    let mut configs = HashMap::new();
    
    let mut current_host: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_username: Option<String> = None;
    let mut current_port: Option<u16> = None;
    
    for line in content.lines() {
        let line = line.trim();
        
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        
        let key = parts[0].trim().to_uppercase();
        let value = parts[1].trim();
        
        match key.as_str() {
            "HOST" => {
                // Save the previous host if it exists
                if let (Some(host), Some(hostname)) = (&current_host, &current_hostname) {
                    configs.insert(host.clone(), SshHostConfig {
                        hostname: hostname.clone(),
                        username: current_username.clone().unwrap_or_else(whoami::username),
                        port: current_port.unwrap_or(22),
                    });
                }
                
                // Start a new host
                current_host = Some(value.to_string());
                current_hostname = None;
                current_username = None;
                current_port = None;
            },
            "HOSTNAME" => {
                current_hostname = Some(value.to_string());
            },
            "USER" => {
                current_username = Some(value.to_string());
            },
            "PORT" => {
                current_port = Some(value.parse::<u16>().unwrap_or(22));
            },
            _ => {}
        }
    }
    
    // Save the last host
    if let (Some(host), Some(hostname)) = (&current_host, &current_hostname) {
        configs.insert(host.clone(), SshHostConfig {
            hostname: hostname.clone(),
            username: current_username.clone().unwrap_or_else(whoami::username),
            port: current_port.unwrap_or(22),
        });
    }
    
    Ok(configs)
}

/// Find the private SSH key in standard locations
fn find_private_key() -> Result<String, Box<dyn Error>> {
    let ssh_dir = dirs::home_dir()
        .ok_or("Could not find home directory")?
        .join(".ssh");
    
    let common_keys = ["id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"];
    
    for key in &common_keys {
        let path = ssh_dir.join(key);
        if path.exists() {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    
    Err("No SSH private key found".into())
}

/// Execute a command via SSH and return the output
fn run_ssh_command(sess: &Session, cmd: &str) -> Result<String, Box<dyn Error>> {
    let mut channel = sess.channel_session()?;
    channel.exec(cmd)?;
    
    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    
    channel.wait_close()?;
    
    Ok(output)
}

/// Search for the Massa log file in the user's directory
fn find_massa_log_file(sess: &Session) -> Result<String, Box<dyn Error>> {
    // Try several possible locations for the Massa log file
    let possible_paths = [
        "./massa/massa-node/logs/log.txt",       // Current directory structure
        "/home/$USER/massa/massa-node/logs.txt",  // User's massa folder
    ];
    
    // Command to try to find the log file in multiple locations
    let find_cmd = format!(
        "for path in {}; do path=$(eval echo \"$path\"); if [ -f \"$path\" ]; then echo \"$path\"; exit 0; fi; done; echo \"NOT_FOUND\"",
        possible_paths.join(" ")
    );
    
    let output = run_ssh_command(sess, &find_cmd)?;
    let log_path = output.trim();
    
    if log_path == "NOT_FOUND" {
        // If automatic detection failed, try using find
        println!("  Trying to locate log file using find command...");
        let find_cmd = "find ~ -type f -path \"*/massa/massa-node/logs/node.log\" -o -path \"*/.massa/massa-node/logs/node.log\" 2>/dev/null | head -n 1";
        let output = run_ssh_command(sess, find_cmd)?;
        let log_path = output.trim();
        
        if log_path.is_empty() {
            return Err("Could not find Massa node log file".into());
        }
        
        return Ok(log_path.to_string());
    }
    
    Ok(log_path.to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Explicitly define servers to check (hardcoded list)
    const SERVERS_TO_CHECK: &[&str] = &[
        "buildnet0",
        "buildnet2",
        "labnet1",
    ];
    
    // Prompt for SSH passphrase
    print!("Enter your SSH passphrase (leave empty if none): ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;
    let passphrase = if passphrase.is_empty() { None } else { Some(passphrase) };
    
    // Prompt for log file path
    print!("Log file path on servers (leave empty = autodiscover): ");
    io::stdout().flush()?;
    let mut log_path = String::new();
    io::stdin().read_line(&mut log_path)?;
    let log_path = log_path.trim().to_string();

    // Number of hashes to retrieve
    print!("Number of latest hashes to check (default: 10): ");
    io::stdout().flush()?;
    let mut hashes_count = String::new();
    io::stdin().read_line(&mut hashes_count)?;
    let hashes_count = hashes_count.trim().parse::<usize>().unwrap_or(10);
    
    // Read the local SSH configuration
    println!("\nReading local SSH configuration...");
    let ssh_configs = read_ssh_config()?;
    
    // Display found SSH configurations for the specified servers
    println!("SSH configurations found for specified servers:");
    for &server_name in SERVERS_TO_CHECK {
        if let Some(config) = ssh_configs.get(server_name) {
            println!("  ✓ {}: {}@{}:{}", server_name, config.username, config.hostname, config.port);
        } else {
            println!("  ✗ {} - not found in SSH configuration", server_name);
        }
    }
    
    // Find the private SSH key
    let private_key_path = find_private_key()?;
    println!("Using private key: {}", private_key_path);
    
    // Create server configurations from the hardcoded list
    let servers: Vec<ServerConfig> = SERVERS_TO_CHECK
        .iter()
        .filter(|&host| ssh_configs.contains_key(*host))
        .map(|&host| ServerConfig {
            host: host.to_string(),
            log_path: log_path.clone(),
        })
        .collect();
    
    // Display servers to check
    println!("\nServers to check ({}/{}):", servers.len(), SERVERS_TO_CHECK.len());
    for server in &servers {
        println!("  - {} (log: {})", server.host, server.log_path);
    }
    
    // Map to store hashes by server
    let mut server_hashes: HashMap<String, Vec<HashInfo>> = HashMap::new();
    
    // Track successfully connected servers
    let mut connected_servers: Vec<String> = Vec::new();
    
    // Simple regex to extract period, thread, and hash
    let simple_regex = Regex::new(r"period:\s*(\d+).*thread:\s*(\d+).*:\s*([A-Za-z0-9]{16,})")?;
    
    // Progress tracking
    let total_servers = servers.len();
    let mut processed_servers = 0;
    
    println!("\nConnecting to servers and retrieving the {} latest hashes...", hashes_count);
    
    // Process each server
    for mut server in servers {
        processed_servers += 1;
        
        // Get SSH configuration for this host
        let ssh_config = match ssh_configs.get(&server.host) {
            Some(config) => config,
            None => {
                println!("⚠️ [{}/{}] Host '{}' not found in SSH configuration, skipped", 
                         processed_servers, total_servers, server.host);
                continue;
            }
        };
        
        println!("[{}/{}] Connecting to {}@{}:{}...", 
                 processed_servers, total_servers,
                 ssh_config.username, 
                 ssh_config.hostname, 
                 ssh_config.port);
        
        // SSH connection with error handling
        let tcp = match TcpStream::connect(format!("{}:{}", ssh_config.hostname, ssh_config.port)) {
            Ok(stream) => {
                // Set timeouts to avoid hanging
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                stream
            },
            Err(err) => {
                panic!("❌ Connection failed to {}: {}", server.host, err);
            }
        };
        
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        
        // SSH handshake with error handling
        if let Err(err) = sess.handshake() {
            panic!("❌ SSH handshake failed with {}: {}", server.host, err);
        }
        
        // Authentication with private key
        if let Err(err) = sess.userauth_pubkey_file(
            &ssh_config.username, 
            None, 
            Path::new(&private_key_path), 
            passphrase.as_deref()
        ) {
            panic!("❌ Authentication failed for {}: {}", server.host, err);
        }
        
        // Check if authentication was successful
        if !sess.authenticated() {
            panic!("❌ Authentication failed for {}", server.host);
        }

        if server.log_path.is_empty() {
            server.log_path  = find_massa_log_file(&sess).unwrap();
        } 
        
        // Check if log file exists
        let check_cmd = format!("if [ -f \"{}\" ]; then echo 'EXISTS'; else echo 'NOT FOUND'; fi", server.log_path);
        
        let check_result = match run_ssh_command(&sess, &check_cmd) {
            Ok(result) => result.trim().to_string(),
            Err(err) => {
                panic!("⚠️ Error checking log file on {}: {}", server.host, err);
            }
        };
        
        if check_result != "EXISTS" {
            panic!("⚠️ Log file not found on {}: {}", server.host, server.log_path);
        }
        
        connected_servers.push(server.host.clone());
        
        // Extract lines containing hash information
        println!("  Extracting hashes from log file...");
        
        // Method 1: Use grep to extract and filter
        let grep_cmd = format!(
            "grep -a 'hash.*period.*thread' {} | grep -a -v 'current_head' | tail -n 5000",
            server.log_path
        );
        
        let hash_lines = match run_ssh_command(&sess, &grep_cmd) {
            Ok(content) => {
                if content.trim().is_empty() {
                    println!("  Grep found no hash lines, trying with tail...");
                    
                    // If grep fails, use tail and filter client-side
                    match run_ssh_command(&sess, &format!("tail -n 10000 {}", server.log_path)) {
                        Ok(tail_content) => tail_content,
                        Err(tail_err) => {
                            println!("❌ Failed to retrieve with tail on {}: {}", 
                                     server.host, tail_err);
                            
                            // Last chance: read end of file with dd
                            println!("  Attempting with dd...");
                            match run_ssh_command(&sess, 
                                &format!("dd if={} bs=1M count=5 skip=$((`stat --format=%s {}`/1048576 - 5)) 2>/dev/null",
                                server.log_path, server.log_path)
                            ) {
                                Ok(dd_content) => dd_content,
                                Err(dd_err) => {
                                    println!("❌ All methods failed on {}: {}", 
                                             server.host, dd_err);
                                    connected_servers.pop(); // Remove this server as it failed
                                    continue;
                                }
                            }
                        }
                    }
                } else {
                    content
                }
            },
            Err(_err) => {
                println!("⚠️ Grep command failed on {}. Trying with tail...", server.host);
                
                // If grep fails, use tail
                match run_ssh_command(&sess, &format!("tail -n 10000 {}", server.log_path)) {
                    Ok(tail_content) => tail_content,
                    Err(tail_err) => {
                        println!("❌ Failed to retrieve with tail on {}: {}", 
                                 server.host, tail_err);
                        connected_servers.pop(); // Remove this server as it failed
                        continue;
                    }
                }
            }
        };
        
        // Extract period/thread/hash triplets
        let mut hash_infos = Vec::new();
        let mut seen_periods_threads = HashSet::new();
        let mut matched_lines = 0;
        
        // First pass: use standard regex
        for line in hash_lines.lines() {
            // Filter lines that might contain hash information
            if line.contains("period") && line.contains("thread") && line.contains("hash") {
                if let Some(captures) = simple_regex.captures(line) {
                    matched_lines += 1;
                    
                    // Ensure we have 3 captures
                    if captures.len() < 4 {
                        continue;
                    }
                    
                    // Safely parse numeric values
                    let period = match captures[1].parse::<u64>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    
                    let thread = match captures[2].parse::<u64>() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    
                    let hash = captures[3].to_string();
                    
                    // Simple hash validity check
                    if hash.len() < 16 || !hash.chars().all(|c| c.is_ascii_alphanumeric()) {
                        continue;
                    }
                    
                    let key = (period, thread);
                    
                    // Only take hashes for unique period/thread combinations
                    if !seen_periods_threads.contains(&key) {
                        seen_periods_threads.insert(key);
                        
                        hash_infos.push(HashInfo {
                            period,
                            thread,
                            hash,
                        });
                    }
                }
            }
        }
        
        println!("  Matching lines found: {}", matched_lines);
        println!("  Unique periods/threads: {}", seen_periods_threads.len());
        
        // Try more permissive regex if not enough hashes were found
        if hash_infos.len() < hashes_count && matched_lines < 10 {
            println!("  Not enough hashes found, trying with more permissive regex...");
            
            // More permissive regex that looks for numbers and potential hashes
            let permissive_regex = Regex::new(r"(?:period|p)[^\d]*(\d+)[^\d]*(?:thread|t)[^\d]*(\d+).*?([A-Za-z0-9]{16,})")?;
            
            for line in hash_lines.lines() {
                if let Some(captures) = permissive_regex.captures(line) {
                    if captures.len() < 4 {
                        continue;
                    }
                    
                    let period = match captures[1].parse::<u64>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    
                    let thread = match captures[2].parse::<u64>() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    
                    let hash = captures[3].to_string();
                    
                    if hash.len() < 16 || !hash.chars().all(|c| c.is_ascii_alphanumeric()) {
                        continue;
                    }
                    
                    let key = (period, thread);
                    
                    if !seen_periods_threads.contains(&key) {
                        seen_periods_threads.insert(key);
                        
                        hash_infos.push(HashInfo {
                            period,
                            thread,
                            hash,
                        });
                    }
                }
            }
            
            println!("  After permissive regex - Unique periods/threads: {}", seen_periods_threads.len());
        }
        
        // Sort by descending period and thread (most recent first)
        hash_infos.sort_by(|a, b| {
            match b.period.cmp(&a.period) {
                std::cmp::Ordering::Equal => b.thread.cmp(&a.thread),
                ord => ord,
            }
        });
        
        // Keep only the N most recent
        hash_infos.truncate(hashes_count);
        
        if !hash_infos.is_empty() {
            println!("✅ {} hashes retrieved from {}", hash_infos.len(), server.host);
            
            // Display some hashes for verification
            println!("  Examples of most recent hashes:");
            for (i, hash_info) in hash_infos.iter().take(6).enumerate() {
                println!("    {}. Period: {}, Thread: {}, Hash: {}", 
                         i+1, hash_info.period, hash_info.thread, hash_info.hash);
            }
            
            server_hashes.insert(server.host.clone(), hash_infos);
        } else {
            println!("⚠️ No hashes found in logs of {}", server.host);
            connected_servers.pop(); // Remove server if no hashes found
        }
    }
    
    // Hash verification
    println!("\nVerification Results:");
    println!("=============================");
    
    if server_hashes.is_empty() {
        println!("❌ No data was found in any of the log files.");
        return Ok(());
    }

    // Display the number of successfully connected servers with hash data
    println!("Connected servers with hash data: {}/{}", server_hashes.len(), SERVERS_TO_CHECK.len());
    println!("Servers included in verification: {}", connected_servers.join(", "));
    
    if connected_servers.is_empty() {
        println!("❌ No servers were successfully connected and provided hash data.");
        return Ok(());
    }

    // Find period/thread combinations that exist on all connected servers
    let mut common_period_threads: Option<HashSet<(u64, u64)>> = None;
    
    // First, get all period/thread combinations for each server
    for server_name in &connected_servers {
        if let Some(hashes) = server_hashes.get(server_name) {
            let period_threads: HashSet<(u64, u64)> = hashes.iter()
                .map(|hash_info| (hash_info.period, hash_info.thread))
                .collect();
            
            match &common_period_threads {
                None => common_period_threads = Some(period_threads),
                Some(existing) => {
                    // Find intersection with existing period/threads
                    common_period_threads = Some(
                        existing.intersection(&period_threads)
                                .cloned()
                                .collect()
                    );
                }
            }
        }
    }
    
    let common_period_threads = match common_period_threads {
        Some(set) => set,
        None => {
            println!("❌ No common period/thread combinations found across all servers.");
            return Ok(());
        }
    };
    
    println!("Found {} period/thread combinations common to all servers.", common_period_threads.len());
    
    if common_period_threads.is_empty() {
        println!("❌ No common period/thread combinations found across all servers.");
        return Ok(());
    }
    
    // Build a map of hashes by period and thread but only for common periods/threads
    let mut period_thread_hashes: HashMap<(u64, u64), HashMap<String, Vec<String>>> = HashMap::new();
    
    for (server, hashes) in &server_hashes {
        for hash_info in hashes {
            let key = (hash_info.period, hash_info.thread);
            
            // Only process period/threads that are common to all servers
            if common_period_threads.contains(&key) {
                period_thread_hashes
                    .entry(key)
                    .or_default()
                    .entry(hash_info.hash.clone())
                    .or_default()
                    .push(server.clone());
            }
        }
    }
    
    // Sort periods and threads in descending order
    let mut sorted_keys: Vec<(u64, u64)> = period_thread_hashes.keys().cloned().collect();
    sorted_keys.sort_by(|a, b| {
        match b.0.cmp(&a.0) {
            std::cmp::Ordering::Equal => b.1.cmp(&a.1),
            ord => ord,
        }
    });
    
    let mut has_diff = false;
    let mut total_checked = 0;
    let mut total_with_diffs = 0;
    
    println!("\nAnalyzing {} period/thread combinations common to all {} servers:", 
             sorted_keys.len(), connected_servers.len());
    
    // Check each period/thread combination
    for key in sorted_keys {
        let (period, thread) = key;
        let hash_servers = period_thread_hashes.get(&key).unwrap();
        
        total_checked += 1;
        
        println!("\nPeriod: {}, Thread: {}", period, thread);
        
        if hash_servers.len() == 1 {
            // All servers have the same hash
            let (hash, servers) = hash_servers.iter().next().unwrap();
            
            // Check if we have data from all connected servers
            if servers.len() == connected_servers.len() {
                println!("✅ All servers ({}/{}) have the same hash: {}", 
                         servers.len(), connected_servers.len(), hash);
                println!("   Servers: {}", servers.join(", "));
            } else {
                println!("⚠️ Only {}/{} servers reported this hash: {}", 
                         servers.len(), connected_servers.len(), hash);
                println!("   Servers with data: {}", servers.join(", "));
                
                // Find which servers are missing
                let mut missing_servers = connected_servers.clone();
                missing_servers.retain(|s| !servers.contains(s));
                
                println!("   Missing servers: {}", missing_servers.join(", "));
                
                // Count this as a difference since not all servers have data
                has_diff = true;
                total_with_diffs += 1;
            }
        } else {
            // Different hashes found
            has_diff = true;
            total_with_diffs += 1;
            
            println!("❌ DIFFERENCE DETECTED!");
            
            let total_servers_for_slot: usize = hash_servers.values()
                .map(|servers| servers.len())
                .sum();
            
            if total_servers_for_slot < connected_servers.len() {
                println!("   Note: Only {}/{} servers reported data for this period/thread", 
                         total_servers_for_slot, connected_servers.len());
            }
            
            // Sort hashes by number of servers (descending)
            let mut sorted_hashes: Vec<_> = hash_servers.iter().collect();
            sorted_hashes.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
            
            for (hash, servers) in sorted_hashes {
                let percentage = (servers.len() as f64 / connected_servers.len() as f64 * 100.0) as u64;
                println!("   Hash: {} ({}/{} servers, {}%)", 
                         hash, servers.len(), connected_servers.len(), percentage);
                println!("     Servers: {}", servers.join(", "));
            }
        }
    }
    
    // Final summary
    println!("\nFinal Summary:");
    println!("=============");
    println!("Servers with hash data: {}/{}", connected_servers.len(), SERVERS_TO_CHECK.len());
    println!("Periods/threads common to all servers: {}", total_checked);
    
    if has_diff {
        println!("❌ Differences detected: {} periods/threads ({}%)", 
                 total_with_diffs, (total_with_diffs as f64 / total_checked as f64 * 100.0) as u64);
        println!("⚠️ HASH DIFFERENCES DETECTED BETWEEN SERVERS!");
        println!("   For the same period and thread, some servers have different hashes.");
    } else if total_checked > 0 {
        println!("✅ ALL HASHES MATCH PERFECTLY BETWEEN SERVERS.");
        println!("   For each period and thread, all servers reported the same hash.");
    } else {
        println!("⚠️ No periods/threads could be compared (not enough common data).");
    }
    
    Ok(())
}
