# PhishGuard AI 🛡️

PhishGuard AI is a comprehensive cybersecurity solution designed to detect and block phishing attempts in real-time. It combines advanced brand similarity heuristics, VirusTotal integration, and a proactive Chrome Extension to keep users safe from malicious websites.

## 🚀 Key Features

- **Real-time URL Scanning**: Analyze any domain for SSL validity, WHOIS age, and brand mimicking.
- **Chrome Extension**: Proactive protection with a "Guard Curtain" that blocks malicious sites before they load.
- **Autocomplete Suggestions**: Smart domain hints as you type for faster and safer browsing.
- **Detailed Diagnostic Reports**: Understand exactly *why* a site was flagged with detailed reasoning.
- **Visual Analysis**: Built-in screenshot analysis to detect brand identity theft.

## 🛠️ Tech Stack

- **Backend**: Python, Flask, Selenium, OpenCV
- **Extension**: Manifest V3, JavaScript, WebNavigation API
- **Heuristics**: Levenshtein Distance, Brand Keyword Matching
- **APIs**: VirusTotal v3

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Urldetection.git
   cd Urldetection
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Environment Variables**:
   Create a `.env` file in the root directory and add your VirusTotal API Key:
   ```env
   VT_API_KEY=your_virustotal_key_here
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

## 🧩 Chrome Extension Setup

1. Open `chrome://extensions/` in your browser.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder in this project.
4. Pin the **PhishGuard AI Companion**.

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
