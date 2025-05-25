// lib/talosintelligence.ts
import axios from 'axios';
import * as cheerio from 'cheerio'; // Menggunakan impor ES6 style

export interface TalosReputation {
  ip: string;
  verdict: string | null; // e.g., "Malicious", "Neutral", "Untrusted", "Favorable"
  emailVolume?: string;
  webReputation?: string;
  errorMessage?: string;
}

class TalosScrapingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TalosScrapingError";
  }
}

export async function getTalosReputation(ip: string): Promise<TalosReputation> {
  const url = `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(ip)}`;
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  };

  try {
    const response = await axios.get(url, { headers });
    const html = response.data;
    const $ = cheerio.load(html);

    // Selector ini sangat rentan terhadap perubahan di situs Talos
    // Perlu diuji dan disesuaikan jika layout mereka berubah.
    // Selector pada gambar Anda adalah: 'div.indicator label span.label'
    // Saya akan mencoba menyesuaikannya, tetapi ini mungkin perlu update.
    let verdict: string | null = null;

    // Coba beberapa selector umum untuk reputasi IP di Talos
    // Ini adalah bagian yang paling rapuh
    const reputationElement = $(
        '#email-volume-graph-header b, ' + // Seringkali reputasi ada di sini
        '.new-legacy-label.text-center, ' + // Pola lain
        'div.indicator.new-indicator-label span.label, ' + // Mirip contoh Anda
        'td:contains("Weighted Reputation") + td, ' + // Pola tabel lama
        'div.rep-label-container div.new-indicator-label span.label' // variasi lain
        ).first();


    if (reputationElement.length > 0) {
      verdict = reputationElement.text().trim();
      // Normalisasi beberapa nilai umum
      if (verdict.toLowerCase().includes('favorable')) verdict = 'Favorable';
      else if (verdict.toLowerCase().includes('neutral')) verdict = 'Neutral';
      else if (verdict.toLowerCase().includes('unfavorable') || verdict.toLowerCase().includes('poor')) verdict = 'Unfavorable/Poor';
      else if (verdict.toLowerCase().includes('suspicious')) verdict = 'Suspicious';
      else if (verdict.toLowerCase().includes('malicious') || verdict.toLowerCase().includes('malware')) verdict = 'Malicious';

    } else {
       // Jika selector utama tidak ditemukan, coba selector dari gambar Anda secara spesifik
       const specificVerdictElement = $('div.indicator label span.label').first();
       if (specificVerdictElement.length > 0) {
           verdict = specificVerdictElement.text().trim();
       } else {
           console.warn(`Talos: Could not find reputation element for IP ${ip} with primary selectors.`);
       }
    }
    
    if (!verdict) {
        // Fallback jika tidak ada yang terdeteksi
        const pageTitle = $('title').text();
        if (pageTitle.toLowerCase().includes("not found") || pageTitle.toLowerCase().includes("error")) {
            verdict = "Not Found/Error";
        } else if ($('body:contains("nable to find any information")').length > 0) {
            verdict = "Not Found";
        } else {
            verdict = "Unknown (Selector miss)";
        }
    }


    // Anda bisa mencoba mengambil data lain seperti Web Reputation atau Email Volume jika ada & dibutuhkan
    // const webReputation = $('td:contains("Web Reputation") + td').text().trim();
    // const emailVolume = $('td:contains("Email Volume") + td').text().trim();

    return {
      ip: ip,
      verdict: verdict || "Unknown (Parsing failed)",
      // emailVolume: emailVolume || undefined,
      // webReputation: webReputation || undefined,
    };

  } catch (error: any) {
    console.error(`Talos Scraping Error for IP ${ip}:`, error.message);
    if (axios.isAxiosError(error) && error.response?.status === 403) {
        return { ip, verdict: null, errorMessage: "Blocked by Talos (403 Forbidden). Try again later or change IP/User-Agent." };
    }
    return { ip, verdict: null, errorMessage: `Failed to fetch or parse Talos page: ${error.message}` };
  }
}
