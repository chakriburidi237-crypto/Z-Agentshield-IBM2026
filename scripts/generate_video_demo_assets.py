"""
Z-AgentShield: 3-Minute Video Demo Voiceover & Subtitle Generator
Generates:
1. submission/demo_voiceover.mp3 (Synthesized professional voiceover via gTTS)
2. submission/demo_subtitles.srt (Standard SRT subtitle captions)
3. submission/demo_subtitles.vtt (Standard WebVTT subtitle captions)
4. submission/demo_player.html (Interactive synchronized media player with voice & subtitles)
"""

import os
from pathlib import Path
from gtts import gTTS

SUBMISSION_DIR = Path(__file__).resolve().parent.parent / "submission"
SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)

SCRIPTS = [
    {
        "id": 1,
        "start": "00:00:00,000",
        "end": "00:00:28,000",
        "start_vtt": "00:00:00.000",
        "end_vtt": "00:00:28.000",
        "title": "Introduction & Mission",
        "text": (
            "Welcome to Z-AgentShield, an enterprise AI security gateway engineered for IBM LinuxONE "
            "and mission-critical hybrid cloud environments. As autonomous AI agents take real-world actions, "
            "Z-AgentShield intercepts every agent request in real time, enforcing mandatory security policies, "
            "human-in-the-loop review gating, and tamper-evident audit trails."
        ),
    },
    {
        "id": 2,
        "start": "00:00:28,500",
        "end": "00:00:58,000",
        "start_vtt": "00:00:28.500",
        "end_vtt": "00:00:58.000",
        "title": "SOC Operational Overview",
        "text": (
            "Here in the SOC Overview dashboard, security analysts have full visibility into live agent telemetry. "
            "Our showcase displays over 48,000 processed interceptions with a 99.97% service reliability. "
            "Interactive charts track request decision trends, threat block ratios, and real-time risk scores "
            "with sub-100 millisecond evaluation latency."
        ),
    },
    {
        "id": 3,
        "start": "00:00:58,500",
        "end": "00:01:28,000",
        "start_vtt": "00:00:58.500",
        "end_vtt": "00:01:28.000",
        "title": "Prompt Scanner & Threat Detection",
        "text": (
            "Next is our deterministic Prompt Scanner. It proactively inspects incoming agent prompts and payloads "
            "for jailbreaks, direct and indirect prompt injections, and data exfiltration patterns. Every detected "
            "threat is automatically classified and mapped against OWASP Top 10 for LLM Applications and MITRE ATT&CK tactics."
        ),
    },
    {
        "id": 4,
        "start": "00:01:28,500",
        "end": "00:01:58,000",
        "start_vtt": "00:01:28.500",
        "end_vtt": "00:01:58.000",
        "title": "Human Review & Decision Gating",
        "text": (
            "High-risk agent actions immediately trigger human-in-the-loop gating. In the Human Review queue, "
            "SOC analysts inspect the agent identity, claimed intent, and sensitive parameters. Analysts can approve, "
            "reject, or escalate tickets, ensuring that high-consequence operations never execute without explicit "
            "human authorization."
        ),
    },
    {
        "id": 5,
        "start": "00:01:58,500",
        "end": "00:02:28,000",
        "start_vtt": "00:01:58.500",
        "end_vtt": "00:02:28.000",
        "title": "Multi-Role RBAC & Governance",
        "text": (
            "Z-AgentShield enforces strict role-based access control. Security Officers operate in dedicated compliance "
            "governance mode with read-only inspection to satisfy segregation-of-duties regulations. Platform Admins "
            "access host diagnostics, container health, and cryptographic co-processor telemetry, ensuring zero unmonitored privileges."
        ),
    },
    {
        "id": 6,
        "start": "00:02:28,500",
        "end": "00:02:58,000",
        "start_vtt": "00:02:28.500",
        "end_vtt": "00:02:58.000",
        "title": "Cryptographic Audit & LinuxONE Readiness",
        "text": (
            "Finally, our audit subsystem secures every decision with a SHA-256 cryptographic hash chain and automated "
            "sensitive data redaction. Built with native LinuxONE s390x multi-arch containers and CPACF hardware acceleration "
            "readiness, Z-AgentShield delivers the ultimate trust foundation for enterprise AI. Thank you."
        ),
    },
]

def generate_voiceover():
    full_text = " ".join(item["text"] for item in SCRIPTS)
    output_audio = SUBMISSION_DIR / "demo_voiceover.mp3"
    print(f"Synthesizing voiceover audio to: {output_audio}")
    tts = gTTS(text=full_text, lang="en", tld="com", slow=False)
    tts.save(str(output_audio))
    print(f"Voiceover saved successfully ({output_audio.stat().st_size} bytes).")
    return output_audio

def generate_subtitles():
    srt_file = SUBMISSION_DIR / "demo_subtitles.srt"
    vtt_file = SUBMISSION_DIR / "demo_subtitles.vtt"

    with open(srt_file, "w", encoding="utf-8") as f:
        for item in SCRIPTS:
            f.write(f"{item['id']}\n")
            f.write(f"{item['start']} --> {item['end']}\n")
            f.write(f"[{item['title']}] {item['text']}\n\n")

    with open(vtt_file, "w", encoding="utf-8") as f:
        f.write("WEBVTT - Z-AgentShield 3-Minute Demo Presentation Subtitles\n\n")
        for item in SCRIPTS:
            f.write(f"{item['id']}\n")
            f.write(f"{item['start_vtt']} --> {item['end_vtt']}\n")
            f.write(f"[{item['title']}] {item['text']}\n\n")

    print(f"Generated SRT: {srt_file}")
    print(f"Generated VTT: {vtt_file}")

def generate_player_html():
    player_file = SUBMISSION_DIR / "demo_player.html"
    
    cue_cards = ""
    for item in SCRIPTS:
        cue_cards += f"""
        <div class="cue-card" id="cue-{item['id']}">
            <div class="cue-header">
                <span class="cue-time">{item['start_vtt'][:5]} - {item['end_vtt'][:5]}</span>
                <span class="cue-title">Part {item['id']}: {item['title']}</span>
            </div>
            <p class="cue-text">{item['text']}</p>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Z-AgentShield — 3-Minute Video Demo Player & Voiceover</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #1f2937;
            --accent: #38bdf8;
            --accent-grad: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #334155;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 30px 20px;
        }}
        .header {{
            text-align: center;
            max-width: 800px;
            margin-bottom: 25px;
        }}
        .badge {{
            display: inline-block;
            background: rgba(14, 165, 233, 0.15);
            color: var(--accent);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            border: 1px solid rgba(14, 165, 233, 0.3);
        }}
        h1 {{
            font-size: 2.2rem;
            background: var(--accent-grad);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}
        .player-container {{
            width: 100%;
            max-width: 880px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            margin-bottom: 30px;
        }}
        .audio-wrapper {{
            background: var(--surface-card);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }}
        audio {{
            width: 100%;
            height: 48px;
            border-radius: 8px;
            outline: none;
        }}
        .subtitles-box {{
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(56, 189, 248, 0.4);
            border-radius: 12px;
            padding: 20px;
            min-height: 85px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            font-size: 1.15rem;
            line-height: 1.5;
            color: #38bdf8;
            font-weight: 500;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.4);
        }}
        .cue-list {{
            width: 100%;
            max-width: 880px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .cue-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 22px;
            transition: all 0.2s ease;
        }}
        .cue-card.active {{
            border-color: var(--accent);
            background: rgba(14, 165, 233, 0.08);
            transform: translateX(6px);
        }}
        .cue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .cue-time {{
            font-family: monospace;
            background: rgba(255,255,255,0.08);
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.85rem;
            color: var(--accent);
        }}
        .cue-title {{
            font-weight: 600;
            font-size: 1rem;
            color: #e2e8f0;
        }}
        .cue-text {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            line-height: 1.5;
        }}
        .links-bar {{
            margin-top: 25px;
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
            justify-content: center;
        }}
        .btn {{
            background: var(--surface-card);
            color: #f1f5f9;
            text-decoration: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 500;
            border: 1px solid var(--border);
            transition: 0.2s;
        }}
        .btn:hover {{
            border-color: var(--accent);
            color: var(--accent);
        }}
    </style>
</head>
<body>
    <div class="header">
        <span class="badge">IBM Z Datathon 2026 Submission</span>
        <h1>Z-AgentShield Demo Presentation</h1>
        <p class="subtitle">Complete 3-Minute Voiceover Narration with Synchronized Subtitles</p>
    </div>

    <div class="player-container">
        <div class="audio-wrapper">
            <audio id="audioPlayer" controls>
                <source src="demo_voiceover.mp3" type="audio/mpeg">
                <track default kind="subtitles" srclang="en" src="demo_subtitles.vtt" label="English">
                Your browser does not support audio element.
            </audio>
        </div>
        <div class="subtitles-box" id="liveSubtitles">
            Click Play above to start the synchronized audio and subtitles
        </div>
    </div>

    <div class="cue-list">
        {cue_cards}
    </div>

    <div class="links-bar">
        <a class="btn" href="demo_voiceover.mp3" download>📥 Download Audio (MP3)</a>
        <a class="btn" href="demo_subtitles.srt" download>📄 Download Subtitles (SRT)</a>
        <a class="btn" href="demo_subtitles.vtt" download>📄 Download Subtitles (VTT)</a>
        <a class="btn" href="Team-Z-Innovators-Z-AgentShield-Pitch-Deck-DRAFT.pdf" target="_blank">📊 View Pitch Deck (PDF)</a>
    </div>

    <script>
        const audio = document.getElementById('audioPlayer');
        const liveSubtitles = document.getElementById('liveSubtitles');
        const cueCards = document.querySelectorAll('.cue-card');

        const cues = [
            {{ id: 1, start: 0, end: 28, text: "[Introduction & Mission] Welcome to Z-AgentShield, an enterprise AI security gateway engineered for IBM LinuxONE and mission-critical hybrid cloud environments..." }},
            {{ id: 2, start: 28.5, end: 58, text: "[SOC Operational Overview] Here in the SOC Overview dashboard, security analysts have full visibility into live agent telemetry..." }},
            {{ id: 3, start: 58.5, end: 88, text: "[Prompt Scanner & Threat Detection] Next is our deterministic Prompt Scanner. It proactively inspects incoming agent prompts and payloads..." }},
            {{ id: 4, start: 88.5, end: 118, text: "[Human Review & Decision Gating] High-risk agent actions immediately trigger human-in-the-loop gating. In the Human Review queue..." }},
            {{ id: 5, start: 118.5, end: 148, text: "[Multi-Role RBAC & Governance] Z-AgentShield enforces strict role-based access control. Security Officers operate in dedicated compliance..." }},
            {{ id: 6, start: 148.5, end: 178, text: "[Cryptographic Audit & LinuxONE Readiness] Finally, our audit subsystem secures every decision with a SHA-256 cryptographic hash chain..." }}
        ];

        audio.addEventListener('timeupdate', () => {{
            const cur = audio.currentTime;
            let currentCue = cues.find(c => cur >= c.start && cur <= c.end);
            
            cueCards.forEach(c => c.classList.remove('active'));
            
            if (currentCue) {{
                liveSubtitles.innerText = currentCue.text;
                const activeCard = document.getElementById('cue-' + currentCue.id);
                if (activeCard) activeCard.classList.add('active');
            }} else if (cur > 178) {{
                liveSubtitles.innerText = "End of 3-minute presentation. Thank you.";
            }}
        }});
    </script>
</body>
</html>
    """

    with open(player_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"Generated HTML5 player: {player_file}")

if __name__ == "__main__":
    generate_voiceover()
    generate_subtitles()
    generate_player_html()
    print("All video demo assets created successfully in submission/ directory!")
