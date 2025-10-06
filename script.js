// Cyber Month 2025 - Professional Cybersecurity Training Platform
// Housing.com & REA India - Enterprise Security Showcase

// Demo data with detailed information, live links, and interactive content
const demoData = {
    password: {
        title: "Password Strength Demonstration",
        icon: "fas fa-key",
        description: "Experience real-time password cracking and learn advanced security techniques.",
        fullDescription: `
            <h4>🔐 Live Password Security Analysis</h4>
            <p>Watch as we demonstrate the vulnerability of weak passwords through live cracking techniques. This interactive session shows how attackers exploit common password patterns and teaches you to create unbreakable security practices.</p>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: 85%"></div>
            </div>
            <p><strong>Password Strength: Strong (85%)</strong></p>
            
            <h5>🎯 Learning Objectives:</h5>
            <ul>
                <li>Understand password entropy and complexity requirements</li>
                <li>Learn about rainbow tables and hash cracking techniques</li>
                <li>Implement multi-factor authentication strategies</li>
                <li>Master password manager best practices</li>
            </ul>
        `,
        links: [
            { name: "Have I Been Pwned", url: "https://haveibeenpwned.com", icon: "fas fa-exclamation-triangle" },
            { name: "Bitwarden Password Manager", url: "https://bitwarden.com", icon: "fas fa-shield-alt" },
            { name: "NIST Password Guidelines", url: "https://pages.nist.gov/800-63-3/sp800-63b.html", icon: "fas fa-book" },
            { name: "Password Strength Tester", url: "https://www.security.org/how-secure-is-my-password/", icon: "fas fa-test" }
        ]
    },
    phishing: {
        title: "Advanced Phishing Attack Simulation",
        icon: "fas fa-fishing-hook",
        description: "Experience sophisticated social engineering attacks in a controlled environment.",
        fullDescription: `
            <h4>🎣 Sophisticated Social Engineering Lab</h4>
            <p>Participate in realistic phishing scenarios that mirror actual corporate attacks. Learn to identify advanced tactics used by cybercriminals and develop comprehensive defense strategies.</p>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: 92%"></div>
            </div>
            <p><strong>Threat Detection Accuracy: 92%</strong></p>
            
            <h5>🎭 Attack Vectors Covered:</h5>
            <ul>
                <li>Business Email Compromise (BEC) attacks</li>
                <li>Spear phishing with personalized content</li>
                <li>Voice phishing (vishing) scenarios</li>
                <li>SMS phishing (smishing) techniques</li>
            </ul>
        `,
        links: [
            { name: "PhishTank Database", url: "https://phishtank.org", icon: "fas fa-database" },
            { name: "Anti-Phishing Working Group", url: "https://apwg.org", icon: "fas fa-users" },
            { name: "Google Safe Browsing", url: "https://safebrowsing.google.com", icon: "fab fa-google" },
            { name: "KnowBe4 Training", url: "https://www.knowbe4.com", icon: "fas fa-graduation-cap" }
        ]
    },
    ransomware: {
        title: "Ransomware Attack & Recovery Simulation",
        icon: "fas fa-lock",
        description: "Witness controlled ransomware execution and advanced recovery techniques.",
        fullDescription: `
            <h4>🔒 Enterprise Ransomware Response Lab</h4>
            <p>Experience a full ransomware lifecycle in our isolated environment. From initial infection to complete recovery, understand every aspect of modern ransomware threats and enterprise-grade defense strategies.</p>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: 78%"></div>
            </div>
            <p><strong>Recovery Success Rate: 78%</strong></p>
            
            <h5>🛡️ Defense Strategies:</h5>
            <ul>
                <li>Real-time behavior analysis and detection</li>
                <li>Immutable backup strategies and air-gapped storage</li>
                <li>Network segmentation and zero-trust architecture</li>
                <li>Incident response and business continuity planning</li>
            </ul>
        `,
        links: [
            { name: "CISA Ransomware Guide", url: "https://www.cisa.gov/stopransomware", icon: "fas fa-government" },
            { name: "ID Ransomware", url: "https://id-ransomware.malwarehunterteam.com", icon: "fas fa-search" },
            { name: "No More Ransom Project", url: "https://www.nomoreransom.org", icon: "fas fa-unlock" },
            { name: "SANS Incident Response", url: "https://www.sans.org/white-papers/1901/", icon: "fas fa-file-alt" }
        ]
    },
    mobile: {
        title: "Mobile Device Security Assessment",
        icon: "fas fa-mobile-alt",
        description: "Comprehensive mobile security testing and advanced threat analysis.",
        fullDescription: `
            <h4>📱 Advanced Mobile Threat Laboratory</h4>
            <p>Explore the complete mobile attack surface through hands-on demonstrations. From device compromise to data exfiltration, understand mobile-specific threats and implement enterprise mobility management.</p>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: 89%"></div>
            </div>
            <p><strong>Security Posture Score: 89%</strong></p>
            
            <h5>🔍 Attack Scenarios:</h5>
            <ul>
                <li>Advanced Persistent Threat (APT) mobile malware</li>
                <li>Man-in-the-Middle attacks on mobile networks</li>
                <li>Mobile application reverse engineering</li>
                <li>Device fingerprinting and tracking prevention</li>
            </ul>
        `,
        links: [
            { name: "OWASP Mobile Security", url: "https://owasp.org/www-project-mobile-security-testing-guide/", icon: "fab fa-dev" },
            { name: "Android Security Bulletin", url: "https://source.android.com/security/bulletin", icon: "fab fa-android" },
            { name: "iOS Security Guide", url: "https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf", icon: "fab fa-apple" },
            { name: "Mobile Device Management", url: "https://www.nist.gov/publications/guidelines-managing-use-mobile-devices-federal-government", icon: "fas fa-mobile" }
        ]
    },
    forkbomb: {
        title: "Fork Bomb System Analysis",
        icon: "fas fa-bug",
        description: "Understand system resource exhaustion attacks and protection mechanisms.",
        fullDescription: `<h4>💀 System Resource Exhaustion Laboratory</h4><p>Explore how fork bombs work and learn advanced system protection techniques in our isolated environment.</p>`,
        links: [
            { name: "Linux Security Guide", url: "https://www.cisecurity.org/benchmark/linux", icon: "fab fa-linux" }
        ]
    },
    encryption: {
        title: "Advanced Encryption Workshop",
        icon: "fas fa-lock-open",
        description: "Master modern cryptography and secure communication protocols.",
        fullDescription: `<h4>🔐 Cryptography Mastery Lab</h4><p>Deep dive into encryption algorithms, key management, and secure communication implementation.</p>`,
        links: [
            { name: "NIST Cryptographic Standards", url: "https://csrc.nist.gov/publications", icon: "fas fa-book" }
        ]
    },
    forensics: {
        title: "Digital Forensics Investigation",
        icon: "fas fa-search",
        description: "Advanced digital evidence recovery and analysis techniques.",
        fullDescription: `<h4>🔍 Forensic Analysis Laboratory</h4><p>Learn professional digital forensics techniques used by law enforcement and security experts.</p>`,
        links: [
            { name: "Autopsy Digital Forensics", url: "https://www.autopsy.com", icon: "fas fa-search" }
        ]
    },
    usb: {
        title: "USB Security Assessment",
        icon: "fas fa-usb",
        description: "Comprehensive USB threat analysis and protection strategies.",
        fullDescription: `<h4>💾 USB Security Laboratory</h4><p>Understand USB-based attacks and implement enterprise USB security policies.</p>`,
        links: [
            { name: "USB Security Best Practices", url: "https://www.cisa.gov/uscert", icon: "fas fa-shield-alt" }
        ]
    },
    "ios-crash": {
        title: "Mobile Exploit Analysis",
        icon: "fab fa-apple",
        description: "iOS and Android vulnerability research and exploitation.",
        fullDescription: `<h4>📱 Mobile Security Research</h4><p>Explore mobile device vulnerabilities and advanced exploitation techniques.</p>`,
        links: [
            { name: "iOS Security Research", url: "https://developer.apple.com/security/", icon: "fab fa-apple" }
        ]
    },
    wifi: {
        title: "Wireless Security Assessment",
        icon: "fas fa-wifi",
        description: "Enterprise WiFi penetration testing and security analysis.",
        fullDescription: `<h4>📡 Wireless Security Laboratory</h4><p>Learn to secure wireless networks against sophisticated attacks and implement enterprise WiFi security.</p>`,
        links: [
            { name: "WiFi Alliance Security", url: "https://www.wi-fi.org/security", icon: "fas fa-wifi" }
        ]
    },
    mitm: {
        title: "Advanced MITM Detection",
        icon: "fas fa-user-secret",
        description: "Man-in-the-middle attack detection and prevention.",
        fullDescription: `<h4>🕵️ Network Interception Lab</h4><p>Understand and defend against sophisticated network interception attacks.</p>`,
        links: [
            { name: "Network Security Guide", url: "https://www.sans.org/white-papers/", icon: "fas fa-network-wired" }
        ]
    },
    flipper: {
        title: "Hardware Hacking with Flipper Zero",
        icon: "fas fa-microchip",
        description: "IoT and hardware security assessment using Flipper Zero.",
        fullDescription: `<h4>🎮 Hardware Security Laboratory</h4><p>Explore IoT vulnerabilities and hardware-based attack vectors.</p>`,
        links: [
            { name: "Flipper Zero Documentation", url: "https://docs.flipperzero.one/", icon: "fas fa-microchip" }
        ]
    },
    card: {
        title: "Payment Card Security",
        icon: "fas fa-credit-card",
        description: "EMV security analysis and payment fraud prevention.",
        fullDescription: `<h4>💳 Payment Security Laboratory</h4><p>Understand payment card vulnerabilities and implement secure payment processing.</p>`,
        links: [
            { name: "PCI Security Standards", url: "https://www.pcisecuritystandards.org/", icon: "fas fa-credit-card" }
        ]
    },
    badusb: {
        title: "Malicious USB Analysis",
        icon: "fas fa-bolt",
        description: "BadUSB attack vectors and enterprise protection strategies.",
        fullDescription: `<h4>⚡ USB Threat Laboratory</h4><p>Analyze BadUSB attacks and implement comprehensive USB security controls.</p>`,
        links: [
            { name: "USB Security Framework", url: "https://www.nist.gov/cybersecurity", icon: "fas fa-bolt" }
        ]
    },
    bluetooth: {
        title: "Bluetooth Security Analysis",
        icon: "fab fa-bluetooth",
        description: "BLE security assessment and wireless communication protection.",
        fullDescription: `<h4>📶 Bluetooth Security Laboratory</h4><p>Explore Bluetooth vulnerabilities and implement secure wireless communication protocols.</p>`,
        links: [
            { name: "Bluetooth Security Guide", url: "https://www.bluetooth.com/learn-about-bluetooth/tech-overview/", icon: "fab fa-bluetooth" }
        ]
    },
    car: {
        title: "Automotive Cybersecurity",
        icon: "fas fa-car",
        description: "Connected vehicle security and CAN bus analysis.",
        fullDescription: `<h4>🚗 Automotive Security Laboratory</h4><p>Understand connected vehicle threats and implement automotive cybersecurity frameworks.</p>`,
        links: [
            { name: "Automotive Cybersecurity", url: "https://www.nhtsa.gov/technology-innovation/cybersecurity", icon: "fas fa-car" }
        ]
    },
    ducky: {
        title: "Rubber Ducky Exploitation",
        icon: "fas fa-keyboard",
        description: "Advanced keystroke injection and payload development.",
        fullDescription: `<h4>🦆 Keystroke Injection Laboratory</h4><p>Master advanced payload development and keyboard-based attack vectors.</p>`,
        links: [
            { name: "Rubber Ducky Documentation", url: "https://docs.hak5.org/", icon: "fas fa-keyboard" }
        ]
    },
    steganography: {
        title: "Advanced Steganography",
        icon: "fas fa-image",
        description: "Hidden data analysis and covert communication detection.",
        fullDescription: `<h4>🖼️ Steganography Laboratory</h4><p>Explore advanced data hiding techniques and implement steganography detection systems.</p>`,
        links: [
            { name: "Steganography Tools", url: "https://www.sans.org/tools/", icon: "fas fa-image" }
        ]
    },
    email: {
        title: "Email Security Forensics",
        icon: "fas fa-envelope",
        description: "Advanced email threat analysis and forensic investigation.",
        fullDescription: `<h4>📧 Email Forensics Laboratory</h4><p>Master email security analysis and implement advanced threat detection systems.</p>`,
        links: [
            { name: "Email Security Best Practices", url: "https://www.cisa.gov/email-security", icon: "fas fa-envelope" }
        ]
    },
    aws: {
        title: "Cloud Security Architecture",
        icon: "fab fa-aws",
        description: "Enterprise cloud security and AWS threat modeling.",
        fullDescription: `<h4>☁️ Cloud Security Laboratory</h4><p>Implement enterprise cloud security architectures and advanced threat detection systems.</p>`,
        links: [
            { name: "AWS Security Center", url: "https://aws.amazon.com/security/", icon: "fab fa-aws" }
        ]
    },
    docker: {
        title: "Container Security Analysis",
        icon: "fab fa-docker",
        description: "Advanced container security and orchestration protection.",
        fullDescription: `<h4>🐳 Container Security Laboratory</h4><p>Master container security best practices and implement advanced protection mechanisms.</p>`,
        links: [
            { name: "Docker Security Guide", url: "https://docs.docker.com/engine/security/", icon: "fab fa-docker" }
        ]
    },
    kubernetes: {
        title: "Kubernetes Security Hardening",
        icon: "fas fa-cogs",
        description: "Enterprise Kubernetes security and cluster protection.",
        fullDescription: `<h4>⚙️ Kubernetes Security Laboratory</h4><p>Implement advanced Kubernetes security frameworks and cluster hardening techniques.</p>`,
        links: [
            { name: "Kubernetes Security", url: "https://kubernetes.io/docs/concepts/security/", icon: "fas fa-cogs" }
        ]
    },
    "secure-coding": {
        title: "Secure Development Practices",
        icon: "fas fa-code",
        description: "Advanced secure coding and application security testing.",
        fullDescription: `<h4>👨‍💻 Secure Development Laboratory</h4><p>Master secure coding practices and implement comprehensive application security testing frameworks.</p>`,
        links: [
            { name: "OWASP Security Guide", url: "https://owasp.org/www-project-top-ten/", icon: "fas fa-code" }
        ]
    }
};

// Cyber Team Members
const cyberTeam = [
    {
        name: "Dhruv Kalaan",
        role: "Director - Information Security",
        avatar: "DK",
        color: "var(--accent-blue)",
        gradient: "linear-gradient(135deg, #00d4ff, #0066ff)"
    },
    {
        name: "Rahul Malhotra",
        role: "Senior Information Security Engineer",
        avatar: "RM",
        color: "var(--accent-green)",
        gradient: "linear-gradient(135deg, #00ff88, #00cc66)"
    },
    {
        name: "Rupender Singh",
        role: "Senior Information Security Engineer",
        avatar: "RS",
        color: "var(--accent-purple)",
        gradient: "linear-gradient(135deg, #8b5cf6, #6a4c93)"
    },
    {
        name: "Nitesh Arora",
        role: "Lead GRC Analyst",
        avatar: "NA",
        color: "var(--accent-orange)",
        gradient: "linear-gradient(135deg, #ffa726, #ff6600)"
    },
    {
        name: "Rahul Solanki",
        role: "Assistant Manager - IT Operations",
        avatar: "RS2",
        color: "var(--accent-red)",
        gradient: "linear-gradient(135deg, #ff4757, #ee5a6f)"
    },
    {
        name: "Dhruv Awasthi",
        role: "Senior Manager",
        avatar: "DA",
        color: "var(--accent-cyan)",
        gradient: "linear-gradient(135deg, #00e5ff, #00acc1)"
    }
];

// 10-Day Tips & Tricks System with Jokes and Fun Facts
const cyberTips = {
    day1: [
        {
            department: "Development Team",
            icon: "fas fa-code",
            title: "Secure Coding Fundamentals",
            description: "Always validate input data, use parameterized queries, and implement proper authentication. Never trust user input and always sanitize data before processing.",
            action: "✅ Action: Run SAST tools on every commit and fix vulnerabilities before deployment.",
            joke: "🤣 Why do programmers prefer dark mode? Because light attracts bugs!",
            tip: "💡 Pro Tip: Use 'git commit -m' with meaningful messages. Future you will thank present you!",
            shortcut: "⚡ Shortcut: Ctrl+Shift+P in VS Code opens command palette - your gateway to productivity!"
        },
        {
            department: "DevOps & Infrastructure",
            icon: "fas fa-server",
            title: "Container Security Best Practices",
            description: "Scan container images for vulnerabilities, use non-root users, and implement network segmentation. Keep base images updated and minimal.",
            action: "✅ Action: Set up automated vulnerability scanning in your CI/CD pipeline.",
            joke: "🤣 How many DevOps engineers does it take to change a lightbulb? None, that's a hardware problem!",
            tip: "💡 Pro Tip: Always tag your Docker images with specific versions, never use 'latest' in production!",
            shortcut: "⚡ Shortcut: 'docker system prune -a' cleans up all unused containers, images, and volumes!"
        },
        {
            department: "Product Management",
            icon: "fas fa-chart-line",
            title: "Privacy by Design",
            description: "Integrate security requirements from the start of product development. Consider data minimization, user consent, and privacy impact assessments.",
            action: "✅ Action: Include security requirements in every user story and sprint planning.",
            joke: "🤣 A product manager walks into a bar. Asks for a beer. Asks for 0 beers. Asks for 999999999 beers. Asks for -1 beers. Asks for a lizard.",
            tip: "💡 Pro Tip: Create a security checklist template for all new features - consistency is key!",
            shortcut: "⚡ Shortcut: Use JIRA filters to quickly find security-related tickets: 'labels = security'"
        },
        {
            department: "Security Operations Center",
            icon: "fas fa-shield-alt",
            title: "Incident Detection & Response",
            description: "Monitor security events 24/7, establish clear escalation procedures, and maintain incident response playbooks. Quick detection saves millions!",
            action: "✅ Action: Review and update incident response procedures quarterly.",
            joke: "🤣 Security alert at 3 AM: 'It's probably nothing...' Narrator: 'It was definitely something.'",
            tip: "💡 Pro Tip: Create automation rules for common false positives to reduce alert fatigue!",
            shortcut: "⚡ Shortcut: Use SOAR platforms to automate repetitive security tasks and responses!"
        },
        {
            department: "Application Security",
            icon: "fas fa-lock",
            title: "OWASP Top 10 Prevention",
            description: "Master the OWASP Top 10 vulnerabilities and implement preventive measures. Focus on injection attacks, broken authentication, and XSS prevention.",
            action: "✅ Action: Conduct OWASP-based security assessments for all applications.",
            joke: "🤣 Developer: 'I fixed the SQL injection!' Hacker: 'Great, now let me try NoSQL injection!'",
            tip: "💡 Pro Tip: Use security headers like CSP, X-Frame-Options, and HSTS to add defense layers!",
            shortcut: "⚡ Shortcut: SecurityHeaders.com - instantly check your website's security headers!"
        }
    ],
    day2: [
        {
            department: "Marketing & Sales",
            icon: "fas fa-bullhorn",
            title: "Social Engineering Awareness",
            description: "Be cautious of phishing emails targeting customer data. Verify requests for sensitive information through multiple channels before sharing.",
            action: "✅ Action: Implement a verification process for all customer data requests.",
            joke: "🤣 Why don't hackers like knock-knock jokes? Because they prefer brute force entry!",
            tip: "💡 Pro Tip: Always hover over links to see the actual URL before clicking - phishers love lookalike domains!",
            shortcut: "⚡ Shortcut: Use Ctrl+K in most browsers to quickly search and verify suspicious URLs!"
        },
        {
            department: "UI/UX Design",
            icon: "fas fa-paint-brush",
            title: "Secure Design Patterns",
            description: "Design interfaces that guide users toward secure behaviors. Use clear security indicators, implement proper session timeouts, and avoid dark patterns.",
            action: "✅ Action: Review designs for security implications and user privacy protection.",
            joke: "🤣 Designer: 'I made the password field invisible for a cleaner look!' Security: 'That's... not how it works.'",
            tip: "💡 Pro Tip: Always show password strength indicators and make 2FA options prominently visible!",
            shortcut: "⚡ Shortcut: Use Figma's Security Design Kit for pre-built secure UI components!"
        },
        {
            department: "QA & Testing",
            icon: "fas fa-bug",
            title: "Security Testing Integration",
            description: "Include security test cases in your testing strategy. Test for common vulnerabilities like XSS, CSRF, and injection attacks.",
            action: "✅ Action: Add security testing to your standard QA checklist and automation suite.",
            joke: "🤣 QA Engineer walks into a bar. Orders 1 beer. Orders 0 beers. Orders 999999999 beers. Orders -1 beers. Orders a lizard.",
            tip: "💡 Pro Tip: Use OWASP ZAP for automated security testing - it's free and catches common vulnerabilities!",
            shortcut: "⚡ Shortcut: Burp Suite's Intruder tool can automate testing for injection vulnerabilities!"
        },
        {
            department: "Email Security",
            icon: "fas fa-envelope-shield",
            title: "Email Authentication Protocols",
            description: "Implement SPF, DKIM, and DMARC to prevent email spoofing and phishing. Protect your domain reputation and customer trust.",
            action: "✅ Action: Configure SPF, DKIM, and DMARC records for all company domains.",
            joke: "🤣 Phisher: 'I sent from your domain!' DMARC: 'Nice try, but I'm gonna stop you right there.'",
            tip: "💡 Pro Tip: Start DMARC with p=none, monitor for a month, then move to p=quarantine!",
            shortcut: "⚡ Shortcut: MXToolbox.com - check your email authentication setup in seconds!"
        },
        {
            department: "Identity & Access Management",
            icon: "fas fa-id-badge",
            title: "Zero Trust Architecture",
            description: "Never trust, always verify. Implement least privilege access, continuous verification, and assume breach mentality in your security design.",
            action: "✅ Action: Audit all user permissions and implement role-based access control (RBAC).",
            joke: "🤣 'But I've worked here for 10 years!' Zero Trust: 'That's nice, please authenticate again.'",
            tip: "💡 Pro Tip: Use Just-In-Time (JIT) access for administrative privileges - grant only when needed!",
            shortcut: "⚡ Shortcut: Azure AD Privileged Identity Management automates JIT access controls!"
        }
    ],
    day3: [
        {
            department: "Data Analytics",
            icon: "fas fa-chart-bar",
            title: "Data Protection & Analytics",
            description: "Anonymize personal data in analytics, implement data retention policies, and ensure compliance with privacy regulations like GDPR.",
            action: "✅ Action: Audit all data collection and implement automatic data anonymization.",
            joke: "🤣 Data Analyst: 'I can predict everything!' Security: 'Can you predict when you'll accidentally expose PII?'",
            tip: "💡 Pro Tip: Use differential privacy techniques to add noise to datasets while maintaining statistical accuracy!",
            shortcut: "⚡ Shortcut: pandas.DataFrame.drop() with subset=['PII_columns'] for quick data sanitization!"
        },
        {
            department: "Cloud Engineering",
            icon: "fas fa-cloud",
            title: "Cloud Security Fundamentals",
            description: "Use IAM roles with least privilege, enable logging and monitoring, and encrypt data in transit and at rest. Regular security audits are essential.",
            action: "✅ Action: Review and tighten IAM policies, enable GuardDuty or similar threat detection.",
            joke: "🤣 There is no cloud, it's just someone else's computer... that you forgot to secure!",
            tip: "💡 Pro Tip: Enable MFA on all AWS root accounts and use temporary credentials with STS!",
            shortcut: "⚡ Shortcut: 'aws iam get-account-authorization-details' shows all permissions in one command!"
        },
        {
            department: "Mobile Development",
            icon: "fas fa-mobile-alt",
            title: "Mobile App Security",
            description: "Implement certificate pinning, secure data storage, and proper session management. Avoid storing sensitive data on device storage.",
            action: "✅ Action: Conduct mobile security assessment and implement OWASP Mobile security guidelines.",
            joke: "🤣 Mobile Dev: 'It works on my phone!' Security: 'Great, now try it on a rooted device with a proxy!'",
            tip: "💡 Pro Tip: Use Android Keystore and iOS Keychain for secure credential storage, never SharedPreferences!",
            shortcut: "⚡ Shortcut: Use react-native-keychain for cross-platform secure storage in React Native!"
        },
        {
            department: "Penetration Testing",
            icon: "fas fa-user-ninja",
            title: "Ethical Hacking Essentials",
            description: "Think like an attacker to defend better. Regular penetration testing reveals vulnerabilities before malicious actors find them.",
            action: "✅ Action: Schedule quarterly penetration tests and fix critical findings immediately.",
            joke: "🤣 Pentester: 'I'm in!' Developer: 'But that's impossible!' Pentester: 'You left debug mode on in production.'",
            tip: "💡 Pro Tip: Always get written authorization before testing - unauthorized testing is illegal hacking!",
            shortcut: "⚡ Shortcut: Metasploit's 'db_nmap' combines scanning with automatic vulnerability detection!"
        },
        {
            department: "Blockchain Security",
            icon: "fas fa-cube",
            title: "Smart Contract Security",
            description: "Audit smart contracts for reentrancy attacks, integer overflows, and access control issues. Once deployed, bugs become permanent!",
            action: "✅ Action: Use automated tools like Mythril and manual audits before mainnet deployment.",
            joke: "🤣 'Code is law!' they said. 'What could go wrong?' asked the $50M hack.",
            tip: "💡 Pro Tip: Use OpenZeppelin's audited libraries instead of writing security features from scratch!",
            shortcut: "⚡ Shortcut: 'slither .' runs comprehensive smart contract security analysis in one command!"
        }
    ],
    day4: [
        {
            department: "Backend Engineering",
            icon: "fas fa-database",
            title: "API Security Excellence",
            description: "Implement rate limiting, proper authentication, input validation, and API versioning. Use HTTPS everywhere and monitor for suspicious activity.",
            action: "✅ Action: Implement API security testing and monitoring in production environments.",
            joke: "🤣 Backend Dev: 'My API is RESTful!' Hacker: 'Great, it'll REST peacefully after I DOS it!'",
            tip: "💡 Pro Tip: Implement API keys with automatic rotation and use JWT tokens with short expiration times!",
            shortcut: "⚡ Shortcut: Use Express.js rate-limit middleware: 'npm install express-rate-limit' for quick implementation!"
        },
        {
            department: "Frontend Engineering",
            icon: "fas fa-laptop-code",
            title: "Client-Side Security",
            description: "Implement Content Security Policy (CSP), avoid storing secrets in client code, and sanitize user inputs to prevent XSS attacks.",
            action: "✅ Action: Audit frontend code for security vulnerabilities and implement CSP headers.",
            joke: "🤣 Frontend Dev: 'I minified my code!' Hacker: 'Ctrl+Shift+I, now it's prettified!'",
            tip: "💡 Pro Tip: Use DOMPurify for sanitizing HTML and never use dangerouslySetInnerHTML without sanitization!",
            shortcut: "⚡ Shortcut: Chrome DevTools Security tab shows all mixed content and certificate issues instantly!"
        },
        {
            department: "Site Reliability Engineering",
            icon: "fas fa-tools",
            title: "Infrastructure Monitoring",
            description: "Monitor for security incidents, implement alerting for suspicious activities, and maintain incident response procedures.",
            action: "✅ Action: Set up security monitoring dashboards and incident response playbooks.",
            joke: "🤣 SRE: 'Everything is monitored!' Also SRE: 'Why didn't we get alerted about that breach?'",
            tip: "💡 Pro Tip: Set up anomaly detection with ML - unusual patterns often indicate security incidents!",
            shortcut: "⚡ Shortcut: Prometheus + Grafana + AlertManager = Your security monitoring trinity!"
        },
        {
            department: "Threat Intelligence",
            icon: "fas fa-brain",
            title: "Proactive Threat Hunting",
            description: "Don't wait for alerts - actively hunt for threats in your environment. Use threat intelligence feeds to stay ahead of emerging attacks.",
            action: "✅ Action: Subscribe to threat intelligence feeds and conduct weekly threat hunting exercises.",
            joke: "🤣 'No news is good news!' Threat Hunter: 'No news means your monitoring is broken.'",
            tip: "💡 Pro Tip: Use MITRE ATT&CK framework to map and hunt for specific adversary techniques!",
            shortcut: "⚡ Shortcut: TheHive + Cortex = Automated threat intelligence and incident response platform!"
        },
        {
            department: "Vulnerability Management",
            icon: "fas fa-bug-slash",
            title: "Patch Management Strategy",
            description: "Timely patching prevents 85% of successful attacks. Establish patch cycles, test thoroughly, and prioritize critical vulnerabilities.",
            action: "✅ Action: Implement automated vulnerability scanning and establish SLAs for patching.",
            joke: "🤣 'We'll patch it next quarter!' Ransomware: 'Thanks for the advance notice!'",
            tip: "💡 Pro Tip: Use CVSS scores combined with threat intelligence to prioritize patching efforts!",
            shortcut: "⚡ Shortcut: Qualys VMDR or Rapid7 InsightVM for continuous vulnerability assessment!"
        }
    ],
    day5: [
        {
            department: "Compliance & Legal",
            icon: "fas fa-gavel",
            title: "Regulatory Compliance",
            description: "Stay updated with data protection laws, conduct regular compliance audits, and maintain documentation for security controls.",
            action: "✅ Action: Schedule quarterly compliance reviews and update privacy policies.",
            joke: "🤣 Lawyer: 'Is this GDPR compliant?' Dev: 'I'll add a cookie banner and hope for the best!'",
            tip: "💡 Pro Tip: Privacy by Design isn't just a buzzword - implement it from day one to avoid costly retrofits!",
            shortcut: "⚡ Shortcut: Use automated compliance tools like OneTrust or TrustArc for continuous monitoring!"
        },
        {
            department: "HR & People Operations",
            icon: "fas fa-users",
            title: "Security Awareness Training",
            description: "Conduct regular security training, implement phishing simulation programs, and establish clear security policies for employees.",
            action: "✅ Action: Schedule monthly security awareness sessions and phishing tests.",
            joke: "🤣 Why did the security expert go broke? Because he used all his cache!",
            tip: "💡 Pro Tip: Use password managers and enable 2FA on all accounts - it's not paranoia if they're really after your data!",
            shortcut: "⚡ Shortcut: Windows+L locks your computer instantly - use it every time you leave your desk!"
        },
        {
            department: "Finance & Operations",
            icon: "fas fa-money-bill-wave",
            title: "Financial Data Protection",
            description: "Secure payment processing, implement fraud detection, and ensure PCI DSS compliance for handling financial transactions.",
            action: "✅ Action: Review and audit all financial data handling processes and systems.",
            joke: "🤣 Finance: 'We saved money by building our own payment system!' Security: 'You mean you built your own vulnerabilities?'",
            tip: "💡 Pro Tip: Never store credit card numbers - use tokenization services like Stripe or Square!",
            shortcut: "⚡ Shortcut: PCI DSS Quick Reference Guide - focus on the 12 requirements first!"
        },
        {
            department: "Physical Security",
            icon: "fas fa-building-lock",
            title: "Office & Data Center Security",
            description: "Digital security starts with physical security. Implement access controls, CCTV monitoring, and secure disposal of hardware.",
            action: "✅ Action: Audit physical access logs and implement visitor management systems.",
            joke: "🤣 'Our servers are secure!' Meanwhile: The server room door is propped open with a fire extinguisher.",
            tip: "💡 Pro Tip: Use RFID badges with anti-cloning features and require PIN codes for sensitive areas!",
            shortcut: "⚡ Shortcut: Implement clean desk policy - sensitive documents should never be left unattended!"
        },
        {
            department: "Insider Threat Detection",
            icon: "fas fa-user-secret",
            title: "Behavioral Analytics",
            description: "Monitor for unusual user behavior patterns. Most data breaches involve insider threats, whether malicious or accidental.",
            action: "✅ Action: Implement User and Entity Behavior Analytics (UEBA) solutions.",
            joke: "🤣 'But they passed the background check!' Security: 'That was before they got that gambling debt.'",
            tip: "💡 Pro Tip: Watch for off-hours access, large data downloads, and access to systems outside job role!",
            shortcut: "⚡ Shortcut: Splunk UBA or Microsoft Sentinel can automatically detect anomalous behavior patterns!"
        }
    ],
    day6: [
        {
            department: "Customer Support",
            icon: "fas fa-headset",
            title: "Customer Data Protection",
            description: "Verify customer identity before sharing information, use secure communication channels, and maintain confidentiality of customer interactions.",
            action: "✅ Action: Implement customer verification procedures and secure communication protocols.",
            joke: "🤣 Support: 'Have you tried turning your security off and on again?' Security: 'NO! NEVER DO THAT!'",
            tip: "💡 Pro Tip: Use callback verification - if someone claims to be a customer, call them back on their registered number!",
            shortcut: "⚡ Shortcut: Set up templated security questions in your CRM for consistent verification!"
        },
        {
            department: "Research & Development",
            icon: "fas fa-flask",
            title: "Secure Innovation",
            description: "Consider security implications in research projects, protect intellectual property, and ensure secure data handling in experiments.",
            action: "✅ Action: Include security review in all R&D project proposals and prototypes.",
            joke: "🤣 R&D: 'We invented a new encryption!' Security: 'Great, now let's use the proven one instead!'",
            tip: "💡 Pro Tip: Always use established cryptographic libraries - don't roll your own crypto!",
            shortcut: "⚡ Shortcut: Use git-secret to encrypt sensitive files in your research repositories!"
        },
        {
            department: "Business Intelligence",
            icon: "fas fa-chart-pie",
            title: "Secure Analytics Practices",
            description: "Implement data governance, ensure proper access controls for sensitive reports, and anonymize data for analysis purposes.",
            action: "✅ Action: Review all BI reports for data sensitivity and implement appropriate access controls.",
            joke: "🤣 BI Analyst: 'I found an interesting pattern!' Security: 'Is that pattern someone's SSN?'",
            tip: "💡 Pro Tip: Implement row-level security in your BI tools - not everyone needs to see everything!",
            shortcut: "⚡ Shortcut: Power BI RLS (Row-Level Security) can be set up with simple DAX expressions!"
        },
        {
            department: "Supply Chain Security",
            icon: "fas fa-truck",
            title: "Third-Party Risk Management",
            description: "Your security is only as strong as your weakest vendor. Assess supplier security, monitor software dependencies, and verify component integrity.",
            action: "✅ Action: Conduct security assessments of all critical vendors and suppliers.",
            joke: "🤣 'It's from a trusted source!' SolarWinds hack: 'Allow me to introduce myself.'",
            tip: "💡 Pro Tip: Use Software Bill of Materials (SBOM) to track all components and their vulnerabilities!",
            shortcut: "⚡ Shortcut: 'npm audit' and 'pip-audit' quickly check for vulnerable dependencies!"
        },
        {
            department: "Disaster Recovery",
            icon: "fas fa-fire-extinguisher",
            title: "Business Continuity Planning",
            description: "Hope for the best, plan for the worst. Regular backups, tested recovery procedures, and redundant systems save businesses.",
            action: "✅ Action: Test disaster recovery procedures quarterly and update runbooks.",
            joke: "🤣 'We have backups!' DR Test: 'Great! Now try restoring from them... Oh, they're corrupted?'",
            tip: "💡 Pro Tip: Follow the 3-2-1 backup rule: 3 copies, 2 different media types, 1 offsite!",
            shortcut: "⚡ Shortcut: Automate backup testing with restoration scripts - untested backups are just prayers!"
        }
    ],
    day7: [
        {
            department: "Content & SEO",
            icon: "fas fa-search",
            title: "Content Security Management",
            description: "Secure CMS platforms, avoid exposing sensitive information in public content, and implement secure file upload procedures.",
            action: "✅ Action: Audit all published content for sensitive information and secure CMS access.",
            joke: "🤣 SEO Expert: 'I got us to #1 on Google!' Security: 'For exposing our API keys? Not ideal!'",
            tip: "💡 Pro Tip: Always sanitize file uploads - a .jpg file can contain malicious PHP code!",
            shortcut: "⚡ Shortcut: Use robots.txt to prevent search engines from indexing sensitive directories!"
        },
        {
            department: "Partnership & Integrations",
            icon: "fas fa-handshake",
            title: "Third-Party Security",
            description: "Conduct security assessments of partners, implement secure API integrations, and maintain vendor security standards.",
            action: "✅ Action: Review all third-party integrations and implement security assessment procedures.",
            joke: "🤣 Partner: 'Our API is secure, trust us!' Security: 'That's exactly what someone insecure would say!'",
            tip: "💡 Pro Tip: Always use OAuth 2.0 for third-party integrations - never share passwords!",
            shortcut: "⚡ Shortcut: Use Postman's security testing features to validate partner APIs!"
        },
        {
            department: "Executive Leadership",
            icon: "fas fa-crown",
            title: "Security Governance",
            description: "Establish security budgets, promote security culture, and ensure security considerations in strategic decisions.",
            action: "✅ Action: Schedule monthly security briefings and allocate resources for security initiatives.",
            joke: "🤣 CEO: 'Why do we need security budget?' CISO: 'Why do you need insurance?'",
            tip: "💡 Pro Tip: Security ROI = (Risk Reduction x Asset Value) - Security Investment. Do the math!",
            shortcut: "⚡ Shortcut: NIST Cybersecurity Framework provides executive-level security metrics!"
        },
        {
            department: "IoT Security",
            icon: "fas fa-wifi",
            title: "Internet of Things Protection",
            description: "Secure smart devices, implement network segmentation for IoT, and regularly update firmware. Each device is a potential entry point!",
            action: "✅ Action: Create IoT device inventory and implement separate network segments.",
            joke: "🤣 'My toaster is smart!' Hacker: 'Smart enough to join my botnet army!'",
            tip: "💡 Pro Tip: Change default passwords on ALL IoT devices - Shodan.io finds them in seconds!",
            shortcut: "⚡ Shortcut: Use VLANs to isolate IoT devices from critical business networks!"
        },
        {
            department: "Encryption Services",
            icon: "fas fa-key",
            title: "Cryptographic Key Management",
            description: "Proper key management is crucial. Rotate keys regularly, use hardware security modules (HSMs), and never hardcode secrets.",
            action: "✅ Action: Implement centralized key management system and rotation policies.",
            joke: "🤣 'I encrypted everything!' Also Dev: 'The key? It's in the same database.'",
            tip: "💡 Pro Tip: Use envelope encryption - encrypt your data keys with master keys stored in KMS!",
            shortcut: "⚡ Shortcut: HashiCorp Vault provides enterprise-grade secret management with audit trails!"
        }
    ],
    day8: [
        {
            department: "Network Engineering",
            icon: "fas fa-network-wired",
            title: "Network Security Excellence",
            description: "Implement network segmentation, monitor traffic for anomalies, and maintain firewall rules with least privilege access.",
            action: "✅ Action: Conduct network security audit and implement zero-trust architecture principles.",
            joke: "🤣 Network Admin: 'I'll just open port 22 for everyone!' Security: 'And I'll just update my resume!'",
            tip: "💡 Pro Tip: Use VLANs to segment your network - broadcast storms can't cross VLAN boundaries!",
            shortcut: "⚡ Shortcut: 'netstat -tulpn' shows all open ports on Linux - close what you don't need!"
        },
        {
            department: "Database Administration",
            icon: "fas fa-database",
            title: "Database Security Best Practices",
            description: "Encrypt sensitive data, implement proper access controls, and regularly backup and test recovery procedures.",
            action: "✅ Action: Review database permissions and implement encryption for sensitive data fields.",
            joke: "🤣 DBA: 'I backed up everything!' Also DBA: 'Wait, where did I store the encryption keys?'",
            tip: "💡 Pro Tip: Use transparent data encryption (TDE) for at-rest encryption without app changes!",
            shortcut: "⚡ Shortcut: PostgreSQL: 'REVOKE ALL ON SCHEMA public FROM public;' - start with zero permissions!"
        },
        {
            department: "System Administration",
            icon: "fas fa-cogs",
            title: "System Hardening Practices",
            description: "Keep systems updated, implement proper logging, and use configuration management for security settings.",
            action: "✅ Action: Implement automated patch management and security configuration baselines.",
            joke: "🤣 SysAdmin: 'I disabled the firewall to fix the issue!' Security: 'You've become the issue!'",
            tip: "💡 Pro Tip: Use configuration management tools like Ansible to ensure consistent security settings!",
            shortcut: "⚡ Shortcut: 'fail2ban' automatically blocks IPs after failed login attempts - install it everywhere!"
        },
        {
            department: "Security Architecture",
            icon: "fas fa-project-diagram",
            title: "Defense in Depth Strategy",
            description: "Layer your security controls like an onion. Multiple barriers mean attackers must breach several defenses, not just one.",
            action: "✅ Action: Map current security controls and identify single points of failure.",
            joke: "🤣 'We have a firewall!' Attacker: 'Cool, I'll just use port 443 like everyone else.'",
            tip: "💡 Pro Tip: Combine preventive, detective, and corrective controls at each layer!",
            shortcut: "⚡ Shortcut: Use the SABSA framework to align security architecture with business needs!"
        },
        {
            department: "Forensics & Investigation",
            icon: "fas fa-fingerprint",
            title: "Digital Evidence Collection",
            description: "Proper evidence handling can make or break legal cases. Maintain chain of custody, use write-blockers, and document everything.",
            action: "✅ Action: Create incident response evidence collection procedures and train the team.",
            joke: "🤣 'I fixed the compromised server!' Legal: 'You mean you destroyed all the evidence?'",
            tip: "💡 Pro Tip: Always work on forensic copies, never the original evidence!",
            shortcut: "⚡ Shortcut: 'dd' command creates bit-for-bit copies, but use FTK Imager for legal admissibility!"
        }
    ],
    day9: [
        {
            department: "Security Operations",
            icon: "fas fa-shield-alt",
            title: "24/7 Security Monitoring",
            description: "Implement SIEM solutions, establish incident response procedures, and maintain threat intelligence feeds.",
            action: "✅ Action: Review and test incident response procedures and update security monitoring rules.",
            joke: "🤣 SOC Analyst: 'Another false positive!' Also SOC: 'Wait, this one's real! RED ALERT!'",
            tip: "💡 Pro Tip: Tune your SIEM rules regularly - alert fatigue leads to missed real threats!",
            shortcut: "⚡ Shortcut: Splunk query for failed logins: 'index=auth action=failure | stats count by user'!"
        },
        {
            department: "Risk Management",
            icon: "fas fa-exclamation-triangle",
            title: "Security Risk Assessment",
            description: "Conduct regular risk assessments, maintain risk registers, and implement appropriate controls for identified risks.",
            action: "✅ Action: Schedule quarterly risk assessments and update risk treatment plans.",
            joke: "🤣 Risk Manager: 'The probability is low!' Murphy's Law: 'Hold my beer!'",
            tip: "💡 Pro Tip: Use the FAIR model for quantitative risk analysis - numbers speak louder than colors!",
            shortcut: "⚡ Shortcut: Risk = Threat x Vulnerability x Impact. If any is zero, risk is zero!"
        },
        {
            department: "Audit & Compliance",
            icon: "fas fa-clipboard-check",
            title: "Security Audit Excellence",
            description: "Conduct regular security audits, maintain audit trails, and ensure compliance with security frameworks.",
            action: "✅ Action: Plan annual security audits and implement continuous compliance monitoring.",
            joke: "🤣 Auditor: 'Show me your security documentation!' IT: 'It's secure... somewhere in SharePoint!'",
            tip: "💡 Pro Tip: Automate evidence collection - screenshots and manual logs won't scale!",
            shortcut: "⚡ Shortcut: Use AWS Config or Azure Policy for continuous compliance monitoring!"
        },
        {
            department: "Red Team Operations",
            icon: "fas fa-user-ninja",
            title: "Adversarial Simulation",
            description: "Think like an attacker to find weaknesses before they do. Red team exercises reveal blind spots in your defenses.",
            action: "✅ Action: Schedule annual red team exercises and purple team collaboration sessions.",
            joke: "🤣 Blue Team: 'We're secure!' Red Team: 'We're already in your network, check Slack.'",
            tip: "💡 Pro Tip: Document everything during red team ops - your tactics help blue team improve!",
            shortcut: "⚡ Shortcut: Cobalt Strike + BloodHound = Active Directory compromise in minutes!"
        },
        {
            department: "Security Automation",
            icon: "fas fa-robot",
            title: "SOAR Implementation",
            description: "Automate repetitive security tasks. Let machines handle the mundane so humans can focus on complex threats.",
            action: "✅ Action: Identify top 5 repetitive tasks and create automation playbooks.",
            joke: "🤣 'We'll automate security!' Also: 'Why did the bot just block the CEO?'",
            tip: "💡 Pro Tip: Start small - automate one process perfectly before expanding!",
            shortcut: "⚡ Shortcut: Phantom/Splunk SOAR has pre-built playbooks for common security workflows!"
        }
    ],
    day10: [
        {
            department: "All Departments",
            icon: "fas fa-globe",
            title: "Collective Security Culture",
            description: "Security is everyone's responsibility. Foster a culture where security considerations are part of daily operations across all teams.",
            action: "✅ Action: Implement security champions program and regular cross-departmental security meetings.",
            joke: "🤣 Everyone: 'Security is IT's job!' IT: 'Your password is Password123!' Everyone: 'Security is everyone's job!'",
            tip: "💡 Pro Tip: Gamify security training - people remember what they enjoy learning!",
            shortcut: "⚡ Shortcut: Create a Slack channel #security-wins to celebrate good security practices!"
        },
        {
            department: "Innovation Teams",
            icon: "fas fa-lightbulb",
            title: "Secure Innovation Mindset",
            description: "Balance innovation with security, implement security-by-design principles, and consider privacy implications in new features.",
            action: "✅ Action: Include security experts in innovation workshops and feature planning sessions.",
            joke: "🤣 Innovation Team: 'We'll add security later!' Narrator: 'They, in fact, did not add security later!'",
            tip: "💡 Pro Tip: Security debt accumulates interest - pay it early or pay 10x later!",
            shortcut: "⚡ Shortcut: Add 'Security Impact' as a mandatory field in your feature request template!"
        },
        {
            department: "Crisis Management",
            icon: "fas fa-ambulance",
            title: "Security Incident Response",
            description: "Prepare for security incidents with clear communication plans, defined roles, and practiced procedures for various scenario types.",
            action: "✅ Action: Conduct tabletop exercises and update emergency contact lists for security incidents.",
            joke: "🤣 During breach: 'Who's in charge?' Everyone: 'Not it!' Hacker: 'Thanks for the chaos!'",
            tip: "💡 Pro Tip: The first hour of incident response determines the next month of cleanup - prepare!",
            shortcut: "⚡ Shortcut: RACI matrix for incidents - who's Responsible, Accountable, Consulted, Informed!"
        },
        {
            department: "Security Champions",
            icon: "fas fa-medal",
            title: "Building Security Advocates",
            description: "Create security champions in every team. These advocates bridge the gap between security and business operations.",
            action: "✅ Action: Identify and train security champions with specialized workshops and certifications.",
            joke: "🤣 'I'm not a security expert!' Champion program: 'Not yet, but you will be!'",
            tip: "💡 Pro Tip: Empower champions with direct access to security team and decision-making authority!",
            shortcut: "⚡ Shortcut: Monthly champion meetings + dedicated Slack channel = effective security culture!"
        },
        {
            department: "Future of Security",
            icon: "fas fa-rocket",
            title: "AI & Machine Learning Security",
            description: "The future is AI-powered threats and defenses. Understand model poisoning, adversarial attacks, and AI-enhanced security tools.",
            action: "✅ Action: Explore AI security tools and understand AI-specific threat vectors.",
            joke: "🤣 'AI will solve security!' AI: 'I've learned from your data... including the breaches.'",
            tip: "💡 Pro Tip: Use AI for anomaly detection but always keep humans in the decision loop!",
            shortcut: "⚡ Shortcut: TensorFlow Privacy library helps implement differential privacy in ML models!"
        }
    ]
};

// Presentation Mode Variables
let presentationActive = false;
let autoShuffleActive = false;
let currentDemoIndex = 0;
let shuffleInterval;
let demoKeys = Object.keys(demoData);

// Tips & Tricks Variables
let tipsActive = false;
let currentDay = 1;
let currentTipIndex = 0;
let tipsInterval;
let visitedDays = new Set(); // Track visited days

// Stay Tuned Variables
let stayTunedActive = false;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeAnimations();
    initializeInteractivity();
    initializeBackgroundEffects();
    initializeParallax();
    generateTeamSection();
    initializeControlsVisibility();
    
    // Load visited days from localStorage
    const savedVisitedDays = localStorage.getItem('visitedDays');
    if (savedVisitedDays) {
        visitedDays = new Set(JSON.parse(savedVisitedDays));
    }
    
    // Initialize incident contact alert
    initializeIncidentAlert();
});

// Advanced GSAP Animations
function initializeAnimations() {
    // Animate cards on scroll
    gsap.registerPlugin(ScrollTrigger);
    
    gsap.from('.demo-card', {
        duration: 0.8,
        y: 50,
        opacity: 0,
        stagger: 0.1,
        ease: "back.out(1.7)",
        scrollTrigger: {
            trigger: '.cyber-grid',
            start: 'top 80%',
            end: 'bottom 20%',
            toggleActions: 'play none none reverse'
        }
    });

    // Header animation
    gsap.from('.header-content', {
        duration: 1.2,
        y: -30,
        opacity: 0,
        ease: "elastic.out(1, 0.3)"
    });

    // Floating badge animation
    gsap.to('.floating-badge', {
        duration: 4,
        rotation: 360,
        repeat: -1,
        ease: "none"
    });
}

// Interactive functionality
function initializeInteractivity() {
    document.querySelectorAll('.demo-card').forEach((card, index) => {
        card.addEventListener('click', function() {
            const demoType = this.getAttribute('data-demo');
            if (demoData[demoType]) {
                openModal(demoData[demoType]);
            }
            
            // Add click animation
            gsap.to(this, {
                duration: 0.1,
                scale: 0.95,
                yoyo: true,
                repeat: 1,
                ease: "power2.inOut"
            });
        });

        // Hover effects
        card.addEventListener('mouseenter', function() {
            gsap.to(this, {
                duration: 0.3,
                y: -12,
                scale: 1.02,
                boxShadow: "0 25px 50px -12px rgba(0, 212, 255, 0.25)",
                ease: "power2.out"
            });
        });

        card.addEventListener('mouseleave', function() {
            gsap.to(this, {
                duration: 0.3,
                y: 0,
                scale: 1,
                boxShadow: "0 10px 25px -3px rgba(0, 0, 0, 0.1)",
                ease: "power2.out"
            });
        });
    });
}

// Advanced background effects with Three.js
function initializeBackgroundEffects() {
    const canvas = document.getElementById('backgroundCanvas');
    if (!canvas) return;
    
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.zIndex = '-1';
    canvas.style.pointerEvents = 'none';

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true });
    renderer.setSize(window.innerWidth, window.innerHeight);

    // Create floating particles
    const particleGeometry = new THREE.BufferGeometry();
    const particleCount = 200;
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i++) {
        positions[i] = (Math.random() - 0.5) * 10;
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const particleMaterial = new THREE.PointsMaterial({
        color: 0x00d4ff,
        size: 0.02,
        transparent: true,
        opacity: 0.6
    });

    const particles = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particles);

    camera.position.z = 5;

    function animate() {
        requestAnimationFrame(animate);
        particles.rotation.x += 0.001;
        particles.rotation.y += 0.002;
        renderer.render(scene, camera);
    }

    animate();

    // Handle window resize
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// Parallax scrolling effects
function initializeParallax() {
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const parallaxElements = document.querySelectorAll('.header');
        
        parallaxElements.forEach(element => {
            const speed = 0.5;
            element.style.transform = `translateY(${scrolled * speed}px)`;
        });
    });
}

// Generate team section
function generateTeamSection() {
    // Team section will be generated in presentation mode
}

// Hover controls visibility
function initializeControlsVisibility() {
    const controls = document.getElementById('presentationControls');
    if (!controls) return;
    
    // Hide controls initially
    controls.classList.add('hidden');
    
    // Show on mouse movement
    let hideTimeout;
    document.addEventListener('mousemove', () => {
        controls.classList.remove('hidden');
        clearTimeout(hideTimeout);
        
        // Hide after 3 seconds of no movement
        hideTimeout = setTimeout(() => {
            if (presentationActive || tipsActive) {
                controls.classList.add('hidden');
            }
        }, 3000);
    });
}

// Spectacular Presentation Mode Functions
function togglePresentationMode() {
    const presentationMode = document.getElementById('presentationMode');
    const toggleBtn = document.getElementById('presentationToggle');
    
    presentationActive = !presentationActive;
    
    if (presentationActive) {
        presentationMode.classList.add('active');
        toggleBtn.classList.add('active');
        toggleBtn.innerHTML = '<i class="fas fa-times"></i> Exit TV';
        initializePresentationMode();
        enterFullscreen();
        // Show incident alert more frequently in presentation mode
        showIncidentAlert();
    } else {
        presentationMode.classList.remove('active');
        toggleBtn.classList.remove('active');
        toggleBtn.innerHTML = '<i class="fas fa-tv"></i> TV Mode';
        stopAutoShuffle();
        exitFullscreen();
    }
}

function toggleAutoShuffle() {
    const shuffleBtn = document.getElementById('shuffleToggle');
    
    autoShuffleActive = !autoShuffleActive;
    
    if (autoShuffleActive) {
        shuffleBtn.classList.add('active');
        shuffleBtn.innerHTML = '<i class="fas fa-pause"></i> Pause';
        startAutoShuffle();
    } else {
        shuffleBtn.classList.remove('active');
        shuffleBtn.innerHTML = '<i class="fas fa-shuffle"></i> Auto Shuffle';
        stopAutoShuffle();
    }
}

function startAutoShuffle() {
    shuffleInterval = setInterval(() => {
        nextDemo();
    }, 60000); // Change demo every 60 seconds (1 minute) for better readability
}

function stopAutoShuffle() {
    if (shuffleInterval) {
        clearInterval(shuffleInterval);
        shuffleInterval = null;
    }
}

function nextDemo() {
    currentDemoIndex = (currentDemoIndex + 1) % demoKeys.length;
    updatePresentationCard();
}

function previousDemo() {
    currentDemoIndex = (currentDemoIndex - 1 + demoKeys.length) % demoKeys.length;
    updatePresentationCard();
}

function initializePresentationMode() {
    currentDemoIndex = 0;
    createPresentationStructure();
    updatePresentationCard();
    startPresentationAnimations();
}

function createPresentationStructure() {
    const presentationMode = document.getElementById('presentationMode');
    
    presentationMode.innerHTML = `
        <!-- Dynamic Background Effects -->
        <div class="bg-effect-1"></div>
        <div class="bg-effect-2"></div>
        <div class="bg-effect-3"></div>
        
        <!-- Presentation Header with Branding -->
        <div class="presentation-header">
            <div class="presentation-brand housing-brand">
                <div class="brand-icon housing-brand">H</div>
                <div class="brand-text" style="color: var(--housing-blue);">Housing.com</div>
            </div>
            
            <div class="cyber-title">CYBER MONTH 2025</div>
            
            <div class="presentation-brand rea-brand">
                <div class="brand-icon rea-brand">R</div>
                <div class="brand-text" style="color: var(--rea-orange);">REA India</div>
            </div>
        </div>
        
        <!-- Main Presentation Area -->
        <div class="presentation-main">
            <div class="presentation-card" id="presentationCard">
                <!-- Dynamic content will be inserted here -->
            </div>
        </div>
        
        <!-- Cyber Team Section -->
        <div class="cyber-team-section">
            <div class="team-header">
                <div class="team-title">Connect with Our Cyber Team</div>
                <div class="team-subtitle">Elite Security Professionals</div>
            </div>
            <div class="team-grid" id="teamGrid">
                ${cyberTeam.map(member => `
                    <div class="team-member">
                        <div class="member-avatar" style="background: linear-gradient(135deg, ${member.color}, ${member.color}88);">
                            ${member.avatar}
                        </div>
                        <div class="member-name">${member.name}</div>
                        <div class="member-role">${member.role}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function updatePresentationCard() {
    const card = document.getElementById('presentationCard');
    const demoKey = demoKeys[currentDemoIndex];
    const demo = demoData[demoKey];
    
    if (!card || !demo) return;
    
    // Add exiting animation to current card
    card.classList.add('exiting');
    
    // Generate random gradient for each card
    const gradients = [
        'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
        'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
        'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
        'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
        'linear-gradient(135deg, #30cfd0 0%, #330867 100%)',
        'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)',
        'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)'
    ];
    
    const currentGradient = gradients[currentDemoIndex % gradients.length];
    
    setTimeout(() => {
        // Update card content with enhanced visuals
        card.innerHTML = `
            <div class="card-content">
                <div class="card-icon-section">
                    <div class="card-main-icon" style="background: ${currentGradient}">
                        <i class="${demo.icon}"></i>
                        <div class="icon-ripple"></div>
                    </div>
                    <div class="card-number">#${String(currentDemoIndex + 1).padStart(2, '0')}</div>
                    <div class="lottie-animation" id="cardLottie"></div>
                </div>
                
                <div class="card-info-section">
                    <h2 class="card-title">${demo.title}</h2>
                    <p class="card-description">${demo.description}</p>
                    
                    ${demo.fullDescription ? `
                        <div class="card-extra-info">
                            <div class="info-item">
                                <i class="fas fa-shield-alt"></i>
                                <span>Enterprise-grade security demonstration</span>
                            </div>
                            <div class="info-item">
                                <i class="fas fa-users"></i>
                                <span>Interactive team learning experience</span>
                            </div>
                            <div class="info-item">
                                <i class="fas fa-certificate"></i>
                                <span>Industry-standard best practices</span>
                            </div>
                        </div>
                    ` : ''}
                    
                    <div class="card-tags">
                        <div class="card-tag tag-danger">LIVE DEMO</div>
                        <div class="card-tag tag-info">INTERACTIVE</div>
                        <div class="card-tag tag-success">HANDS-ON</div>
                        <div class="card-tag tag-premium">EXPERT LED</div>
                    </div>
                    
                    <div class="demo-preview-image">
                        ${getPreviewImage(demoKey)}
                    </div>
                </div>
            </div>
        `;
        
        // Remove exiting class and add active class
        card.classList.remove('exiting');
        card.classList.add('active');
        
        // Update background effects based on current demo
        updateBackgroundEffects();
        
        // Load Lottie animation if available
        loadCardLottieAnimation(demoKey);
        
    }, 500); // Half second transition
}

function updateBackgroundEffects() {
    const effects = document.querySelectorAll('.bg-effect-1, .bg-effect-2, .bg-effect-3');
    const particles = document.getElementById('animatedParticles');
    
    // Amazing color palettes for different demos
    const colorPalettes = [
        ['#FF006E', '#8338EC', '#3A86FF'],
        ['#F72585', '#7209B7', '#4361EE'],
        ['#FF4365', '#00D9FF', '#72DDF7'],
        ['#F94144', '#F8961E', '#F9C74F'],
        ['#577590', '#43AA8B', '#90BE6D'],
        ['#2D00F7', '#6A00F4', '#8900F2'],
        ['#D00000', '#DC2F02', '#E85D04'],
        ['#7400B8', '#6930C3', '#5E60CE']
    ];
    
    const currentPalette = colorPalettes[currentDemoIndex % colorPalettes.length];
    
    effects.forEach((effect, index) => {
        const color = currentPalette[index % currentPalette.length];
        const x = 50 + Math.sin((currentDemoIndex + index) * 0.5) * 30;
        const y = 50 + Math.cos((currentDemoIndex + index) * 0.5) * 30;
        
        gsap.to(effect, {
            duration: 3,
            background: `radial-gradient(circle at ${x}% ${y}%, ${color}25 0%, ${color}10 30%, transparent 70%)`,
            ease: "power4.inOut"
        });
    });
    
    // Update particle colors
    if (particles) {
        const particleElements = particles.querySelectorAll('.particle');
        particleElements.forEach((particle, index) => {
            const color = currentPalette[index % currentPalette.length];
            gsap.to(particle, {
                duration: 1.5,
                backgroundColor: color,
                scale: Math.random() * 1.5 + 0.5,
                ease: "power2.inOut"
            });
        });
    }
}

function startPresentationAnimations() {
    // Animate brand logos
    gsap.to('.brand-icon', {
        duration: 3,
        rotation: "random(-5, 5)",
        scale: "random(0.95, 1.05)",
        ease: "sine.inOut",
        repeat: -1,
        yoyo: true,
        stagger: 0.3
    });

    // Cyber title shimmer effect
    gsap.to('.cyber-title', {
        duration: 3,
        backgroundPosition: '200% center',
        ease: "none",
        repeat: -1
    });
    
    // Start team slider animation
    startTeamSlider();
}

function startTeamSlider() {
    const sliderTrack = document.getElementById('teamSliderTrack');
    if (!sliderTrack) return;
    
    let currentPosition = 0;
    const slideWidth = 320; // Width of each slide including gap
    const totalSlides = cyberTeam.length;
    const animationDuration = 3; // Seconds per slide
    
    // Continuous sliding animation
    function slideTeam() {
        currentPosition -= slideWidth;
        
        // Reset position when reaching the end of first set
        if (Math.abs(currentPosition) >= slideWidth * totalSlides) {
            currentPosition = 0;
            gsap.set(sliderTrack, { x: 0 });
        }
        
        gsap.to(sliderTrack, {
            duration: animationDuration * 2, // Slower animation (6 seconds)
            x: currentPosition,
            ease: "power2.inOut",
            onComplete: () => {
                // Add random shuffle effect occasionally
                if (Math.random() > 0.7) {
                    shuffleTeamOrder();
                }
                setTimeout(slideTeam, 2000); // Add 2 second pause between slides
            }
        });
    }
    
    // Start the slider
    slideTeam();
    
    // Auto-vanish after 5 minutes
    setTimeout(() => {
        vanishTeamSlider();
    }, 5 * 60 * 1000); // 5 minutes
}

function shuffleTeamOrder() {
    const slides = document.querySelectorAll('.team-slide');
    const container = document.getElementById('teamSliderTrack');
    
    // Create array of slides
    const slidesArray = Array.from(slides);
    
    // Fisher-Yates shuffle
    for (let i = slidesArray.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [slidesArray[i], slidesArray[j]] = [slidesArray[j], slidesArray[i]];
    }
    
    // Quick shuffle animation
    gsap.to(slides, {
        duration: 0.3,
        opacity: 0,
        scale: 0.8,
        onComplete: () => {
            // Reorder DOM
            slidesArray.forEach(slide => container.appendChild(slide));
            
            // Fade back in
            gsap.to(slides, {
                duration: 0.3,
                opacity: 1,
                scale: 1,
                stagger: 0.05
            });
        }
    });
}

function vanishTeamSlider() {
    const sliderContainer = document.getElementById('teamSliderContainer');
    if (!sliderContainer) return;
    
    // Dramatic vanish animation
    gsap.to('.team-slide', {
        duration: 0.8,
        opacity: 0,
        scale: 0.5,
        y: -50,
        rotation: "random(-20, 20)",
        stagger: 0.1,
        ease: "power2.in",
        onComplete: () => {
            gsap.to(sliderContainer, {
                duration: 0.5,
                opacity: 0,
                onComplete: () => {
                    sliderContainer.style.display = 'none';
                }
            });
        }
    });
}

// Modal system
function openModal(demo) {
    const modal = document.getElementById('demoModal');
    const modalIcon = document.getElementById('modalIcon');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalIcon.innerHTML = `<i class="${demo.icon}"></i>`;
    modalTitle.textContent = demo.title;
    
    let linksHTML = '';
    if (demo.links) {
        linksHTML = `
            <div class="demo-links">
                ${demo.links.map(link => `
                    <a href="${link.url}" target="_blank" class="demo-link">
                        <div class="demo-link-icon">
                            <i class="${link.icon}"></i>
                        </div>
                        <span>${link.name}</span>
                    </a>
                `).join('')}
            </div>
        `;
    }

    modalBody.innerHTML = demo.fullDescription + linksHTML;

    modal.classList.add('show');
    document.body.style.overflow = 'hidden';

    // Animate modal appearance
    gsap.from('.modal-content', {
        duration: 0.5,
        scale: 0.8,
        opacity: 0,
        ease: "back.out(1.7)"
    });
}

function closeModal() {
    const modal = document.getElementById('demoModal');
    modal.classList.remove('show');
    document.body.style.overflow = 'auto';
}

// Fullscreen functionality
function enterFullscreen() {
    const element = document.documentElement;
    if (element.requestFullscreen) {
        element.requestFullscreen();
    } else if (element.webkitRequestFullscreen) {
        element.webkitRequestFullscreen();
    } else if (element.msRequestFullscreen) {
        element.msRequestFullscreen();
    }
}

function exitFullscreen() {
    if (document.exitFullscreen) {
        document.exitFullscreen();
    } else if (document.webkitExitFullscreen) {
        document.webkitExitFullscreen();
    } else if (document.msExitFullscreen) {
        document.msExitFullscreen();
    }
}

// Enhanced keyboard controls for presentation
document.addEventListener('keydown', function(e) {
    if (presentationActive) {
        switch(e.key) {
            case 'ArrowRight':
            case ' ':
                e.preventDefault();
                nextDemo();
                break;
            case 'ArrowLeft':
                e.preventDefault();
                previousDemo();
                break;
            case 's':
            case 'S':
                e.preventDefault();
                toggleAutoShuffle();
                break;
            case 'f':
            case 'F':
                e.preventDefault();
                enterFullscreen();
                break;
        }
    }
    
    if (e.key === 'Escape') {
        if (presentationActive) {
            togglePresentationMode();
        } else {
            closeModal();
        }
    }
});

// Close modal on outside click
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        closeModal();
    }
});

// Live demo counter animation
function animateCounter() {
    const counter = document.querySelector('.live-indicator');
    if (!counter) return;
    
    let count = 0;
    const target = 23;
    const increment = target / 50;

    function updateCounter() {
        count += increment;
        if (count < target) {
            counter.textContent = `${Math.ceil(count)} LIVE DEMOS`;
            requestAnimationFrame(updateCounter);
        } else {
            counter.textContent = `${target} LIVE DEMOS`;
        }
    }

    updateCounter();
}

// Initialize counter after page load
window.addEventListener('load', () => {
    setTimeout(animateCounter, 1000);
});

// Stay Tuned Flyer Functions
function showStayTunedFlyer() {
    const overlay = document.getElementById('stayTunedOverlay');
    if (!overlay) {
        createStayTunedOverlay();
    }
    
    stayTunedActive = true;
    overlay.classList.add('active');
    createExcitementParticles();
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
        if (stayTunedActive) {
            hideStayTunedFlyer();
        }
    }, 10000);
}

function hideStayTunedFlyer() {
    const overlay = document.getElementById('stayTunedOverlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
    stayTunedActive = false;
}

function createStayTunedOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'stayTunedOverlay';
    overlay.className = 'stay-tuned-overlay';
    
    overlay.innerHTML = `
        <div class="flyer-container">
            <div class="flyer-card">
                <button class="close-flyer" onclick="hideStayTunedFlyer()">
                    <i class="fas fa-times"></i>
                </button>
                
                <div class="excitement-particles" id="excitementParticles"></div>
                
                <h1 class="flyer-title">STAY TUNED!</h1>
                <h2 class="flyer-subtitle">Something BIG is Coming...</h2>
                
                <div class="flyer-date">OCTOBER 2024</div>
                <div class="flyer-date" style="font-size: 2rem; color: var(--accent-green);">
                    WEDNESDAYS & THURSDAYS
                </div>
                
                <p class="flyer-message">
                    🚀 Get ready for LIVE cybersecurity demonstrations!<br>
                    🎯 Interactive security challenges<br>
                    🏆 Surprise rewards and recognition<br>
                    💡 Exclusive insights from our security experts
                </p>
                
                <div style="font-size: 1.5rem; color: var(--accent-orange); font-weight: 800;">
                    BE READY FOR SURPRISES! 🎉
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
}

function createExcitementParticles() {
    const container = document.getElementById('excitementParticles');
    if (!container) return;
    
    container.innerHTML = '';
    
    for (let i = 0; i < 20; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 3 + 's';
        particle.style.background = `hsl(${Math.random() * 360}, 70%, 60%)`;
        container.appendChild(particle);
    }
}

// Tips & Tricks Functions
function toggleTipsMode() {
    tipsActive = !tipsActive;
    const tipsBtn = document.getElementById('tipsToggle');
    
    if (tipsActive) {
        showTipsOverlay();
        tipsBtn.classList.add('active');
        tipsBtn.innerHTML = '<i class="fas fa-times"></i> Exit Tips';
        // Show incident alert when entering tips mode
        setTimeout(() => showIncidentAlert(), 2000);
    } else {
        hideTipsOverlay();
        tipsBtn.classList.remove('active');
        tipsBtn.innerHTML = '<i class="fas fa-lightbulb"></i> Tips & Tricks';
    }
}

function showTipsOverlay() {
    let overlay = document.getElementById('tipsOverlay');
    if (!overlay) {
        createTipsOverlay();
        overlay = document.getElementById('tipsOverlay');
    }
    
    overlay.classList.add('active');
    currentDay = 1;
    currentTipIndex = 0;
    
    // Show day selector initially
    showDaySelector();
    
    // Keep day selector visible for 10 seconds to allow selection
    setTimeout(() => {
        // Show a reminder animation before hiding
        const selector = document.getElementById('daySelector');
        if (selector) {
            selector.style.animation = 'selectorReminder 1s ease';
            setTimeout(() => {
                hideDaySelector();
                updateTipsContent();
                startTipsAutoShuffle();
            }, 1000);
        }
    }, 10000);
    
    // Add instruction text
    setTimeout(() => {
        showDaySelectionHint();
    }, 1000);
    
    enterFullscreen();
}

function hideTipsOverlay() {
    const overlay = document.getElementById('tipsOverlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
    stopTipsAutoShuffle();
    exitFullscreen();
}

function createTipsOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'tipsOverlay';
    overlay.className = 'tips-overlay';
    
    overlay.innerHTML = `
        <!-- Dynamic Background Effects -->
        <div class="bg-effect-1"></div>
        <div class="bg-effect-2"></div>
        <div class="bg-effect-3"></div>
        <div class="tips-particles" id="tipsParticles"></div>
        
        <!-- Tips Day Selector Only -->
        <div class="tips-day-selector" id="daySelector">
            <img src="Images/Transparent_logo_housing_with_log.png" alt="Housing.com" class="selector-logo" />
            <div class="day-selector-title">
                <span class="selector-main-title">🎯 Select Your Security Learning Journey 🎯</span>
                <span class="selector-subtitle">Choose a day to explore 5 amazing security tips!</span>
            </div>
            <div class="days-grid">
                ${Array.from({length: 10}, (_, i) => {
                    const dayIcons = ['🔐', '🛡️', '🚀', '💻', '🔍', '🌐', '🎯', '🔧', '📊', '🏆'];
                    return `<button class="day-btn day-btn-${i + 1}" onclick="selectDay(${i + 1})">
                        <span class="day-icon">${dayIcons[i]}</span>
                        <span class="day-number">Day ${i + 1}</span>
                        <span class="day-tips-count">5 Tips</span>
                    </button>`;
                }).join('')}
            </div>
            <div class="selector-instruction" id="selectorInstruction">
                <i class="fas fa-hand-pointer"></i> Click any day to start learning!
            </div>
        </div>
        
        <!-- Main Tips Area -->
        <div class="tips-main">
            <div class="tips-card" id="tipsCard">
                <!-- Dynamic content will be inserted here -->
            </div>
        </div>
        
        <!-- Team Flash Cards for Tips -->
        <div class="tips-team-flash" id="tipsTeamFlash">
            <!-- Team members will flash here -->
        </div>
        
        <!-- Day Selection Hint -->
        <div class="day-selection-hint" id="daySelectionHint">
            <i class="fas fa-lightbulb"></i>
            <span>Press number keys 1-9 or 0 for Day 10 for quick selection!</span>
        </div>
    `;
    
    document.body.appendChild(overlay);
    createTipsParticles();
    startTipsTeamFlash();
}

function startTipsTeamFlash() {
    const container = document.getElementById('tipsTeamFlash');
    if (!container) return;
    
    let memberIndex = 0;
    let flashInterval;
    
    function showNextMember() {
        if (!tipsActive) {
            clearInterval(flashInterval);
            return;
        }
        
        const member = cyberTeam[memberIndex];
        
        // Create flash card
        const flashCard = document.createElement('div');
        flashCard.className = 'tips-flash-member';
        flashCard.innerHTML = `
            <div class="flash-avatar" style="background: ${member.gradient}">
                ${member.avatar}
            </div>
            <div class="flash-info">
                <div class="flash-name">${member.name}</div>
                <div class="flash-role">${member.role}</div>
            </div>
        `;
        
        container.appendChild(flashCard);
        
        // Animate in
        gsap.fromTo(flashCard, 
            {
                x: 100,
                opacity: 0,
                scale: 0.8
            },
            {
                duration: 0.6,
                x: 0,
                opacity: 1,
                scale: 1,
                ease: "power2.out",
                onComplete: () => {
                    // Hold for a moment
                    setTimeout(() => {
                        // Animate out
                        gsap.to(flashCard, {
                            duration: 0.6,
                            x: -100,
                            opacity: 0,
                            scale: 0.8,
                            ease: "power2.in",
                            onComplete: () => {
                                flashCard.remove();
                            }
                        });
                    }, 2000); // Show for 2 seconds
                }
            }
        );
        
        // Move to next member
        memberIndex = (memberIndex + 1) % cyberTeam.length;
    }
    
    // Start flashing after 2 seconds
    setTimeout(() => {
        showNextMember();
        // Continue showing members
        flashInterval = setInterval(showNextMember, 3500); // 3.5 seconds between members
    }, 2000);
}

function selectDay(day) {
    currentDay = day;
    currentTipIndex = 0;
    
    // Mark day as visited
    visitedDays.add(day);
    localStorage.setItem('visitedDays', JSON.stringify([...visitedDays]));
    
    updateDayButtons();
    updateTipsContent();
    
    // Start auto-shuffle for this day
    startTipsAutoShuffle();
}

function updateDayButtons() {
    document.querySelectorAll('.day-btn').forEach((btn, index) => {
        const dayNum = index + 1;
        
        // Remove all classes first
        btn.classList.remove('active', 'visited');
        
        // Add active class for current day
        if (dayNum === currentDay) {
            btn.classList.add('active');
        }
        
        // Add visited class for previously visited days
        if (visitedDays.has(dayNum)) {
            btn.classList.add('visited');
        }
    });
}

function updateTipsContent() {
    const card = document.getElementById('tipsCard');
    const dayKey = `day${currentDay}`;
    const tips = cyberTips[dayKey];
    
    if (!card || !tips || !tips[currentTipIndex]) return;
    
    const tip = tips[currentTipIndex];
    
    // Add exiting animation
    card.classList.remove('active');
    
    // Amazing gradient backgrounds for different departments
    const departmentGradients = {
        'Development Team': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'DevOps & Infrastructure': 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
        'Product Management': 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
        'Marketing & Sales': 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
        'UI/UX Design': 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
        'QA & Testing': 'linear-gradient(135deg, #30cfd0 0%, #330867 100%)',
        'Data Analytics': 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)',
        'Cloud Engineering': 'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)',
        'Mobile Development': 'linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%)',
        'Backend Engineering': 'linear-gradient(135deg, #ff6e7f 0%, #bfe9ff 100%)',
        'Frontend Engineering': 'linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%)',
        'HR & People Operations': 'linear-gradient(135deg, #d299c2 0%, #fef9d7 100%)'
    };
    
    const gradient = departmentGradients[tip.department] || 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
    
    setTimeout(() => {
        card.innerHTML = `
            <div class="tip-content">
                <div class="tip-icon-section">
                    <div class="tip-main-icon" style="background: ${gradient}">
                        <i class="${tip.icon}"></i>
                        <div class="icon-glow"></div>
                    </div>
                    <div class="tip-department">${tip.department}</div>
                    <div class="tip-day-indicator">Day ${currentDay} • Tip ${currentTipIndex + 1}/${tips.length}</div>
                </div>
                
                <div class="tip-info-section">
                    <h2 class="tip-title">${tip.title}</h2>
                    <p class="tip-description">${tip.description}</p>
                    <div class="tip-action">${tip.action}</div>
                    
                    ${tip.joke ? `<div class="tip-joke">${tip.joke}</div>` : ''}
                    ${tip.tip ? `<div class="tip-protip">${tip.tip}</div>` : ''}
                    ${tip.shortcut ? `<div class="tip-shortcut">${tip.shortcut}</div>` : ''}
                    
                    <div class="tip-visual-elements">
                        <div class="security-icon-float">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="security-icon-float" style="animation-delay: 0.5s">
                            <i class="fas fa-lock"></i>
                        </div>
                        <div class="security-icon-float" style="animation-delay: 1s">
                            <i class="fas fa-user-shield"></i>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add active animation
        card.classList.add('active');
        
        // Update background effects
        updateTipsBackgroundEffects(tip.department);
        
    }, 500);
}

function startTipsAutoShuffle() {
    stopTipsAutoShuffle();
    
    tipsInterval = setInterval(() => {
        nextTip();
    }, 60000); // 60 seconds (1 minute) per tip for better readability
}

function stopTipsAutoShuffle() {
    if (tipsInterval) {
        clearInterval(tipsInterval);
        tipsInterval = null;
    }
}

function nextTip() {
    const dayKey = `day${currentDay}`;
    const tips = cyberTips[dayKey];
    
    if (!tips) return;
    
    currentTipIndex = (currentTipIndex + 1) % tips.length;
    updateTipsContent();
}

// Live Demo Banner Functions
function showLiveDemoBanner() {
    let banner = document.getElementById('liveDemoBanner');
    if (!banner) {
        createLiveDemoBanner();
        banner = document.getElementById('liveDemoBanner');
    }
    
    banner.classList.add('show');
    
    // Auto-hide after 8 seconds
    setTimeout(() => {
        hideLiveDemoBanner();
    }, 8000);
}

function hideLiveDemoBanner() {
    const banner = document.getElementById('liveDemoBanner');
    if (banner) {
        banner.classList.remove('show');
    }
}

function createLiveDemoBanner() {
    const banner = document.createElement('div');
    banner.id = 'liveDemoBanner';
    banner.className = 'live-demo-banner';
    banner.innerHTML = `
        🔴 LIVE CYBER MONTH DEMOS • Coming in October • Wednesday & Thursday Sessions • Interactive Security Training 🔴
    `;
    
    document.body.appendChild(banner);
}

// Enhanced presentation mode with flash cards
function createPresentationStructure() {
    const presentationMode = document.getElementById('presentationMode');
    
    presentationMode.innerHTML = `
        <!-- Dynamic Background Effects -->
        <div class="bg-effect-1"></div>
        <div class="bg-effect-2"></div>
        <div class="bg-effect-3"></div>
        <div class="animated-particles" id="animatedParticles"></div>
        
        <!-- Amazing Presentation Header -->
        <div class="presentation-header-amazing">
            <img src="Images/Transparent_logo_housing_with_log.png" alt="Housing.com" class="housing-logo-main" />
            <div class="cyber-title-amazing">
                <span class="cyber-text">CYBER</span>
                <span class="month-text">MONTH</span>
                <span class="year-text">2025</span>
            </div>
        </div>
        
        <!-- October Live Demo Banner -->
        <div class="october-live-banner" id="octoberLiveBanner">
            <div class="banner-glow"></div>
            <div class="banner-content">
                <div class="banner-icon-left">🚨</div>
                <div class="banner-main">
                    <div class="banner-title">🔥 OCTOBER EXCLUSIVE: LIVE IN-PERSON DEMOS! 🔥</div>
                    <div class="banner-subtitle">
                        <span class="subtitle-static">Join us on</span>
                        <span class="subtitle-dynamic">ALL FLOORS</span>
                        <span class="subtitle-static">for mind-blowing security demonstrations!</span>
                    </div>
                    <div class="banner-details">
                        <span class="detail-item"><i class="fas fa-calendar"></i> Every Wednesday & Thursday</span>
                        <span class="detail-item"><i class="fas fa-clock"></i> Multiple Sessions Daily</span>
                        <span class="detail-item"><i class="fas fa-users"></i> Interactive & Hands-On</span>
                    </div>
                    <div class="banner-cta">
                        <span class="cta-word">BE THERE</span>
                        <span class="cta-separator">•</span>
                        <span class="cta-word">BE AWARE</span>
                        <span class="cta-separator">•</span>
                        <span class="cta-word">BE SECURE</span>
                    </div>
                </div>
                <div class="banner-icon-right">🚨</div>
            </div>
            <div class="banner-pulse"></div>
            <div class="banner-particles" id="bannerParticles"></div>
        </div>
        
        <!-- Main Presentation Area -->
        <div class="presentation-main">
            <div class="presentation-card" id="presentationCard">
                <!-- Dynamic content will be inserted here -->
            </div>
        </div>
        
        <!-- Fast-Paced Team Slider -->
        <div class="team-slider-container" id="teamSliderContainer">
            <div class="team-slider-header">Meet Your Cyber Team</div>
            <div class="team-slider-track" id="teamSliderTrack">
                ${cyberTeam.concat(cyberTeam).concat(cyberTeam).map((member, index) => `
                    <div class="team-slide" data-member-index="${index % cyberTeam.length}">
                        <div class="team-slide-avatar" style="background: ${member.gradient}">
                            ${member.avatar}
                        </div>
                        <div class="team-slide-info">
                            <div class="team-slide-name">${member.name}</div>
                            <div class="team-slide-role">${member.role}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    
    // Create animated particles
    createAnimatedParticles();
    
    // Start October banner animations
    startOctoberBannerAnimations();
}

// Auto-show features on page load
window.addEventListener('load', () => {
    setTimeout(animateCounter, 1000);
    
    // Show stay tuned flyer after 3 seconds
    setTimeout(() => {
        showStayTunedFlyer();
    }, 3000);
    
    // Show live demo banner after 15 seconds
    setTimeout(() => {
        showLiveDemoBanner();
    }, 15000);
    
    // Periodically show stay tuned flyer
    setInterval(() => {
        if (!presentationActive && !tipsActive && !stayTunedActive) {
            showStayTunedFlyer();
        }
    }, 60000); // Every minute
});

// Enhanced keyboard controls
document.addEventListener('keydown', function(e) {
    if (presentationActive) {
        switch(e.key) {
            case 'ArrowRight':
            case ' ':
                e.preventDefault();
                nextDemo();
                break;
            case 'ArrowLeft':
                e.preventDefault();
                previousDemo();
                break;
            case 's':
            case 'S':
                e.preventDefault();
                toggleAutoShuffle();
                break;
            case 'f':
            case 'F':
                e.preventDefault();
                enterFullscreen();
                break;
            case 't':
            case 'T':
                e.preventDefault();
                togglePresentationMode();
                toggleTipsMode();
                break;
        }
    } else if (tipsActive) {
        switch(e.key) {
            case 'ArrowRight':
            case ' ':
                e.preventDefault();
                nextTip();
                break;
            case 'ArrowUp':
                e.preventDefault();
                if (currentDay < 10) {
                    selectDay(currentDay + 1);
                }
                break;
            case 'ArrowDown':
                e.preventDefault();
                if (currentDay > 1) {
                    selectDay(currentDay - 1);
                }
                break;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                e.preventDefault();
                selectDay(parseInt(e.key));
                break;
            case '0':
                e.preventDefault();
                selectDay(10);
                break;
        }
    }
    
    if (e.key === 'Escape') {
        if (stayTunedActive) {
            hideStayTunedFlyer();
        } else if (tipsActive) {
            hideTipsOverlay();
            tipsActive = false;
        } else if (presentationActive) {
            togglePresentationMode();
        } else {
            closeModal();
        }
    }
});

// New helper functions
function createAnimatedParticles() {
    const container = document.getElementById('animatedParticles');
    if (!container) return;
    
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 5 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        container.appendChild(particle);
    }
}

function createTipsParticles() {
    const container = document.getElementById('tipsParticles');
    if (!container) return;
    
    for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'tip-particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 3 + 's';
        container.appendChild(particle);
    }
}

function getPreviewImage(demoKey) {
    const imageMap = {
        'password': '<i class="fas fa-key fa-3x" style="color: var(--accent-blue)"></i>',
        'phishing': '<i class="fas fa-fish fa-3x" style="color: var(--accent-orange)"></i>',
        'ransomware': '<i class="fas fa-lock fa-3x" style="color: var(--accent-red)"></i>',
        'mobile': '<i class="fas fa-mobile-alt fa-3x" style="color: var(--accent-green)"></i>',
        'wifi': '<i class="fas fa-wifi fa-3x" style="color: var(--accent-purple)"></i>',
        'usb': '<i class="fas fa-usb fa-3x" style="color: var(--accent-blue)"></i>',
        'docker': '<i class="fab fa-docker fa-3x" style="color: var(--accent-blue)"></i>',
        'aws': '<i class="fab fa-aws fa-3x" style="color: var(--accent-orange)"></i>'
    };
    return imageMap[demoKey] || '<i class="fas fa-shield-alt fa-3x" style="color: var(--accent-green)"></i>';
}

function loadCardLottieAnimation(demoKey) {
    // Placeholder for Lottie animations - can be implemented with actual Lottie files
    const lottieContainer = document.getElementById('cardLottie');
    if (lottieContainer) {
        // For now, we'll add a CSS animation
        lottieContainer.innerHTML = '<div class="lottie-placeholder"><i class="fas fa-shield-alt"></i></div>';
    }
}

function showDaySelector() {
    const selector = document.getElementById('daySelector');
    if (selector) {
        selector.classList.add('active');
    }
}

function hideDaySelector() {
    const selector = document.getElementById('daySelector');
    if (selector) {
        selector.classList.remove('active');
    }
}

function updateTipsBackgroundEffects(department) {
    const effects = document.querySelectorAll('.bg-effect-1, .bg-effect-2, .bg-effect-3');
    
    const departmentColors = {
        'Development Team': ['#667eea', '#764ba2', '#5f3dc4'],
        'DevOps & Infrastructure': ['#f093fb', '#f5576c', '#e94057'],
        'Product Management': ['#4facfe', '#00f2fe', '#0c8599'],
        'Marketing & Sales': ['#43e97b', '#38f9d7', '#0fa573'],
        'UI/UX Design': ['#fa709a', '#fee140', '#f77062']
    };
    
    const colors = departmentColors[department] || ['#667eea', '#764ba2', '#5f3dc4'];
    
    effects.forEach((effect, index) => {
        const color = colors[index % colors.length];
        gsap.to(effect, {
            duration: 2,
            background: `radial-gradient(circle at ${50 + Math.sin(index) * 30}% ${50 + Math.cos(index) * 30}%, ${color}20 0%, transparent 60%)`,
            ease: "power2.inOut"
        });
    });
}

function showDaySelectionHint() {
    const hint = document.getElementById('daySelectionHint');
    if (hint) {
        hint.classList.add('show');
        setTimeout(() => {
            hint.classList.remove('show');
        }, 5000);
    }
}

// October Live Banner Animations
function startOctoberBannerAnimations() {
    const banner = document.getElementById('octoberLiveBanner');
    if (!banner) return;
    
    // Create banner particles
    createBannerParticles();
    
    // Initial entrance animation
    setTimeout(() => {
        banner.classList.add('show');
    }, 2000);
    
    // Periodic emphasis animation
    setInterval(() => {
        banner.classList.add('emphasis');
        setTimeout(() => {
            banner.classList.remove('emphasis');
        }, 3000);
    }, 15000); // Every 15 seconds
    
    // Auto-hide and show cycle
    setInterval(() => {
        banner.classList.remove('show');
        setTimeout(() => {
            banner.classList.add('show');
        }, 5000);
    }, 60000); // Hide for 5 seconds every minute
    
    // Rotate dynamic text
    const dynamicTexts = ['ALL FLOORS', 'EVERY TEAM', 'ALL DEPARTMENTS', 'EVERYONE WELCOME'];
    let textIndex = 0;
    const dynamicElement = banner.querySelector('.subtitle-dynamic');
    
    if (dynamicElement) {
        setInterval(() => {
            textIndex = (textIndex + 1) % dynamicTexts.length;
            dynamicElement.style.opacity = '0';
            setTimeout(() => {
                dynamicElement.textContent = dynamicTexts[textIndex];
                dynamicElement.style.opacity = '1';
            }, 300);
        }, 3000);
    }
}

function createBannerParticles() {
    const container = document.getElementById('bannerParticles');
    if (!container) return;
    
    // Create fire-like particles
    for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'banner-particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 3 + 's';
        particle.style.animationDuration = (3 + Math.random() * 2) + 's';
        
        // Random fire colors
        const colors = ['#ff4757', '#ff6348', '#ffa502', '#ff7675', '#fdcb6e'];
        particle.style.background = colors[Math.floor(Math.random() * colors.length)];
        
        container.appendChild(particle);
    }
}

// Incident Alert System
let incidentAlertInterval;

function initializeIncidentAlert() {
    createIncidentAlertElement();
    startIncidentAlertCycle();
}

function createIncidentAlertElement() {
    const alertDiv = document.createElement('div');
    alertDiv.id = 'incidentAlert';
    alertDiv.className = 'incident-alert';
    alertDiv.innerHTML = `
        <div class="alert-icon">
            <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="alert-content">
            <div class="alert-title">INCIDENT SUPPORT</div>
            <div class="alert-message">In case of incident contact:</div>
            <div class="alert-email">cyberprotect@housing.com</div>
        </div>
        <div class="alert-pulse"></div>
    `;
    document.body.appendChild(alertDiv);
}

function showIncidentAlert() {
    const alert = document.getElementById('incidentAlert');
    if (!alert) return;
    
    // Random position (top or bottom)
    const positions = [
        { bottom: '20%', right: '3%' },
        { top: '20%', right: '3%' },
        { bottom: '30%', left: '3%' },
        { top: '30%', left: '3%' }
    ];
    
    const randomPos = positions[Math.floor(Math.random() * positions.length)];
    
    // Reset styles
    alert.style.top = 'auto';
    alert.style.bottom = 'auto';
    alert.style.left = 'auto';
    alert.style.right = 'auto';
    
    // Apply new position
    Object.keys(randomPos).forEach(key => {
        alert.style[key] = randomPos[key];
    });
    
    // Show alert
    alert.classList.add('show');
    
    // Hide after 5 seconds
    setTimeout(() => {
        alert.classList.remove('show');
    }, 5000);
}

function startIncidentAlertCycle() {
    // Show immediately
    setTimeout(showIncidentAlert, 3000);
    
    // Show every 30 seconds
    incidentAlertInterval = setInterval(() => {
        // Only show if in presentation or tips mode
        if (presentationActive || tipsActive) {
            showIncidentAlert();
        }
    }, 30000);
}

function stopIncidentAlertCycle() {
    if (incidentAlertInterval) {
        clearInterval(incidentAlertInterval);
        incidentAlertInterval = null;
    }
}

// Export functions for global access
window.togglePresentationMode = togglePresentationMode;
window.toggleAutoShuffle = toggleAutoShuffle;
window.nextDemo = nextDemo;
window.closeModal = closeModal;
window.toggleTipsMode = toggleTipsMode;
window.selectDay = selectDay;
window.hideStayTunedFlyer = hideStayTunedFlyer;
