function safeCopyToClipboard(text, msg) {
  if (window.copyToClipboard) {
    window.copyToClipboard(text, msg);
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      if (window.showToast) window.showToast('✓ ' + (msg || 'Panoya kopyalandı!'));
    }).catch(() => fallbackExecCopy(text, msg));
  } else {
    fallbackExecCopy(text, msg);
  }
}
function fallbackExecCopy(text, msg) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    if (window.showToast) window.showToast('✓ ' + (msg || 'Panoya kopyalandı!'));
  } catch(e) {
    if (window.showToast) window.showToast('Kopyalama başarısız');
  }
  document.body.removeChild(ta);
}

let checkDebounceTimer = null;

        // 1. SHA-1 Hash Hesaplama (Hibrit: Secure Context için Web Crypto API, Düz HTTP / IP için Saf JS Motoru)
        async function sha1(str) {
          if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
            try {
              const buffer = new TextEncoder().encode(str);
              const hashBuffer = await window.crypto.subtle.digest('SHA-1', buffer);
              const hashArray = Array.from(new Uint8Array(hashBuffer));
              return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
            } catch(e) {}
          }
          // Fallback: HTTP / IP adreslerinde çalışan sıfır bağımlılıklı saf JS SHA-1
          return pureJsSha1(str);
        }

        function pureJsSha1(msg) {
          function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
          function toHex(n) {
            let s = '';
            for (let i = 7; i >= 0; i--) s += ((n >>> (i * 4)) & 0xf).toString(16);
            return s;
          }
          let str = unescape(encodeURIComponent(msg));
          let l = str.length;
          let words = [];
          for (let i = 0; i < l; i++) {
            words[i >> 2] |= (str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
          }
          words[l >> 2] |= 0x80 << (24 - (l % 4) * 8);
          words[(((l + 8) >> 6) << 4) + 15] = l * 8;

          let H0 = 0x67452301, H1 = 0xefcdab89, H2 = 0x98badcfe, H3 = 0x10325476, H4 = 0xc3d2e1f0;
          let W = new Array(80);

          for (let i = 0; i < words.length; i += 16) {
            for (let t = 0; t < 16; t++) W[t] = words[i + t] | 0;
            for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

            let A = H0, B = H1, C = H2, D = H3, E = H4;
            for (let t = 0; t < 80; t++) {
              let f, k;
              if (t < 20) { f = (B & C) | ((~B) & D); k = 0x5a827999; }
              else if (t < 40) { f = B ^ C ^ D; k = 0x6ed9eba1; }
              else if (t < 60) { f = (B & C) | (B & D) | (C & D); k = 0x8f1bbcdc; }
              else { f = B ^ C ^ D; k = 0xca62c1d6; }

              let temp = (rotl(A, 5) + f + E + k + W[t]) | 0;
              E = D; D = C; C = rotl(B, 30); B = A; A = temp;
            }
            H0 = (H0 + A) | 0; H1 = (H1 + B) | 0; H2 = (H2 + C) | 0; H3 = (H3 + D) | 0; H4 = (H4 + E) | 0;
          }
          return (toHex(H0) + toHex(H1) + toHex(H2) + toHex(H3) + toHex(H4)).toUpperCase();
        }

        // 2. Canlı Güvenlik & Entropi Analizi (Sadece Yerel Hesaplama)
        function analyzePasswordStrengthOnly() {
          const pwd = document.getElementById('input-password').value;
          
          if (!pwd) {
            resetMetrics();
            return;
          }

          // Temel Metrikler
          const len = pwd.length;
          document.getElementById('stat-len').innerText = len;

          const hasLower = /[a-z]/.test(pwd);
          const hasUpper = /[A-Z]/.test(pwd);
          const hasNum = /[0-9]/.test(pwd);
          const hasSym = /[^a-zA-Z0-9]/.test(pwd);
          const diversity = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasNum ? 1 : 0) + (hasSym ? 1 : 0);
          document.getElementById('stat-diversity').innerText = `${diversity}/4`;

          // Entropi hesabı: len * log2(poolSize)
          let poolSize = 0;
          if (hasLower) poolSize += 26;
          if (hasUpper) poolSize += 26;
          if (hasNum) poolSize += 10;
          if (hasSym) poolSize += 32;

          const entropy = poolSize > 0 ? Math.round(len * (Math.log(poolSize) / Math.log(2))) : 0;
          document.getElementById('stat-entropy').innerText = `${entropy} bit`;

          // Kırılma Süresi Tahmini (10 milyar deneme / saniye varsayımı)
          const guesses = Math.pow(poolSize || 2, len);
          const seconds = guesses / 10000000000;
          document.getElementById('stat-crack-time').innerText = formatCrackTime(seconds);

          // Güç Çubuğu
          updateStrengthMeter(entropy, len, diversity);
        }

        function testSamplePassword(sample) {
          const input = document.getElementById('input-password');
          input.value = sample;
          analyzePasswordStrengthOnly();
          runBreachCheck();
        }

        // 3. HaveIBeenPwned k-Anonymity V3 Sızıntı Kontrolü (Açık ve Görsel Telemetri ile)
        async function runBreachCheck() {
          const pwd = document.getElementById('input-password').value;
          if (!pwd) {
            showToast('Lütfen önce test etmek istediğiniz şifreyi yazın!');
            return;
          }

          const btn = document.getElementById('btn-breach-check');
          const btnIcon = document.getElementById('btn-check-icon');
          const btnText = document.getElementById('btn-check-text');
          const card = document.getElementById('breach-result-card');
          const icon = document.getElementById('breach-icon');
          const title = document.getElementById('breach-title');
          const desc = document.getElementById('breach-desc');
          const stats = document.getElementById('breach-stats');
          const telemetry = document.getElementById('breach-telemetry');

          // Buton ve Kartı Yükleme Durumuna Al (DESIGN.md açık kehribar statü)
          btn.disabled = true;
          btn.classList.add('opacity-80', 'cursor-not-allowed');
          btnIcon.innerText = '⏳';
          btnText.innerText = '10+ Milyar Şifre Taranıyor...';

          card.className = 'p-5 rounded-2xl bg-amber-50 border-2 border-amber-300 flex items-start gap-4 transition shadow-sm';
          icon.innerText = '🔍';
          title.innerText = 'k-Anonymity Sızıntı Taraması Yürütülüyor...';
          title.className = 'font-bold text-sm text-amber-950';
          desc.innerText = 'HaveIBeenPwned API V3 protokolü gereğince şifreniz hiçbir yere iletilmeden tarayıcınızda taranıyor.';
          desc.className = 'text-xs text-amber-900 mt-1 leading-relaxed font-medium';
          stats.classList.add('hidden');

          telemetry.classList.remove('hidden');
          document.getElementById('hash-preview').innerText = 'Hesaplanıyor...';
          document.getElementById('prefix-preview').innerText = 'Bekleniyor...';
          document.getElementById('match-status-text').innerText = '3. HIBP Range adayları bekleniyor...';

          try {
            // 1. Adım: Tarayıcı İçi SHA-1 Hash
            const hash = await sha1(pwd);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);

            document.getElementById('hash-preview').innerText = `${prefix}...${suffix.substring(suffix.length - 6)}`;
            document.getElementById('prefix-preview').innerText = `${prefix} (Yalnızca bu 5 karakter sorgulanır)`;

            // 2. Adım: HIBP Range API Sorgusu (Çift Kademeli Güvenli & Yedekli Bağlantı)
            // Standalone: Doğrudan HIBP k-Anonymity API (CORS-açık, şifrenin yalnızca SHA-1 öneki gönderilir)
            let text = '';
            const directRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
              headers: { 'Add-Padding': 'true' }
            });
            if (!directRes.ok) throw new Error('Sızıntı doğrulama servisine erişilemedi');
            text = await directRes.text();

            // 3. Adım: Yerel Eşleştirme (Kalan 35 Karakter)
            const lines = text.split('\n');
            let matchCount = 0;

            for (const rawLine of lines) {
              const line = rawLine.replace('\r', '').trim();
              if (!line) continue;
              const [s, count] = line.split(':');
              if (s && s.toUpperCase() === suffix.toUpperCase()) {
                matchCount = parseInt(count, 10) || 0;
                break;
              }
            }

            document.getElementById('match-status-text').innerText = `3. Dönen ${lines.length} aday arasından yerel karşılaştırma tamamlandı.`;

            // 4. Adım: Sonucu Göster
            renderBreachResult(matchCount);
          } catch(err) {
            card.className = 'p-5 rounded-2xl bg-rose-50 border-2 border-rose-300 flex items-start gap-4 transition shadow-sm';
            icon.innerText = '⚠️';
            title.innerText = 'Tarama Sırasında Hata Oluştu';
            title.className = 'font-bold text-sm text-rose-950';
            desc.innerText = 'Sızıntı servisine erişilemedi: ' + err.message;
            desc.className = 'text-xs text-rose-900 mt-1 leading-relaxed font-medium';
          } finally {
            btn.disabled = false;
            btn.classList.remove('opacity-80', 'cursor-not-allowed');
            btnIcon.innerText = '🔍';
            btnText.innerText = 'Sızıntıyı Kontrol Et';
          }
        }

        function formatCrackTime(sec) {
          if (sec < 1) return '< 1 saniye';
          if (sec < 60) return Math.round(sec) + ' saniye';
          if (sec < 3600) return Math.round(sec / 60) + ' dakika';
          if (sec < 86400) return Math.round(sec / 3600) + ' saat';
          if (sec < 31536000) return Math.round(sec / 86400) + ' gün';
          if (sec < 3153600000) return Math.round(sec / 31536000) + ' yıl';
          return 'Yüzyıllar';
        }

        function updateStrengthMeter(entropy, len, diversity) {
          const meter = document.getElementById('meter-strength');
          const label = document.getElementById('label-strength');

          let score = 0;
          if (len >= 8) score += 20;
          if (len >= 12) score += 20;
          if (len >= 16) score += 10;
          score += (diversity * 10);
          if (entropy >= 60) score += 10;
          score = Math.min(100, score);

          meter.style.width = score + '%';

          if (score < 40) {
            meter.style.backgroundColor = '#ef4444';
            label.innerText = 'Zayıf / Tehlikeli';
            label.className = 'font-bold text-red-400';
          } else if (score < 70) {
            meter.style.backgroundColor = '#f59e0b';
            label.innerText = 'Orta Düzey';
            label.className = 'font-bold text-amber-400';
          } else if (score < 90) {
            meter.style.backgroundColor = '#10b981';
            label.innerText = 'Güçlü';
            label.className = 'font-bold text-emerald-400';
          } else {
            meter.style.backgroundColor = '#06b6d4';
            label.innerText = 'Kırılamaz / Mükemmel';
            label.className = 'font-bold text-cyan-400';
          }
        }

        // 3. k-Anonymity HIBP Kontrolü
        async function checkPwnedPassword(pwd) {
          try {
            const hash = await sha1(pwd);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);

            // Standalone: Doğrudan HIBP k-Anonymity API (CORS-açık)
            const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
              headers: { 'Add-Padding': 'true' }
            });
            const text = await res.text();

            const lines = text.split('\n');
            let matchCount = 0;

            for (const rawLine of lines) {
              const line = rawLine.replace('\r', '').trim();
              if (!line) continue;
              const [s, count] = line.split(':');
              if (s && s.toUpperCase() === suffix.toUpperCase()) {
                matchCount = parseInt(count, 10) || 0;
                break;
              }
            }

            renderBreachResult(matchCount);
          } catch(err) {
            console.error('Sızıntı sorgu hatası:', err);
          }
        }

        function renderBreachResult(count) {
          const card = document.getElementById('breach-result-card');
          const icon = document.getElementById('breach-icon');
          const title = document.getElementById('breach-title');
          const desc = document.getElementById('breach-desc');
          const stats = document.getElementById('breach-stats');

          if (count > 0) {
            card.className = 'p-5 rounded-2xl bg-rose-50 border-2 border-rose-300 flex items-start gap-4 transition shadow-md';
            icon.innerText = '⚠️';
            title.innerText = 'TEHLİKE: Şifreniz Sızdırılmış!';
            title.className = 'font-black text-sm text-rose-950 flex items-center gap-1.5';
            desc.innerText = 'Bu şifre geçmişteki büyük şirket veri sızıntılarında hackerların eline geçmiştir. Saldırganlar bu şifreyi sözlük saldırılarında (credential stuffing) otomatik denerler.';
            desc.className = 'text-xs text-rose-900 mt-1 leading-relaxed font-medium';
            stats.classList.remove('hidden');
            stats.className = 'mt-2.5 px-3 py-1.5 rounded-xl bg-rose-100 text-rose-900 border border-rose-300 font-mono font-bold text-xs inline-block';
            stats.innerText = `🚨 Toplam İfşa Sayısı: ${count.toLocaleString('tr-TR')} kez`;
          } else {
            card.className = 'p-5 rounded-2xl bg-emerald-50 border-2 border-emerald-300 flex items-start gap-4 transition shadow-md';
            icon.innerText = '✅';
            title.innerText = 'Harika! Sızıntılarda Bulunamadı';
            title.className = 'font-black text-sm text-emerald-950';
            desc.innerText = 'Bu şifre bilinen hiçbir veri sızıntısında yer almıyor. Güvenle kullanabilirsiniz.';
            desc.className = 'text-xs text-emerald-900 mt-1 leading-relaxed font-medium';
            stats.classList.add('hidden');
          }
        }

        function resetMetrics() {
          document.getElementById('stat-len').innerText = '0';
          document.getElementById('stat-entropy').innerText = '0 bit';
          document.getElementById('stat-crack-time').innerText = '-';
          document.getElementById('stat-diversity').innerText = '0/4';
          document.getElementById('meter-strength').style.width = '0%';
          document.getElementById('label-strength').innerText = 'Henüz yazılmadı';
          document.getElementById('label-strength').className = 'font-bold text-mistral-slate';

          const card = document.getElementById('breach-result-card');
          card.className = 'p-5 rounded-2xl bg-mistral-cream-light border border-mistral-beige-deep flex items-start gap-4 transition shadow-sm';
          document.getElementById('breach-icon').innerText = '🛡️';
          document.getElementById('breach-title').innerText = 'Sızıntı Taraması Bekleniyor';
          document.getElementById('breach-title').className = 'font-bold text-sm text-mistral-ink';
          const desc = document.getElementById('breach-desc');
          desc.innerText = 'Şifrenizi yazıp \"Sızıntıyı Kontrol Et\" butonuna bastığınızda, 10+ milyar ifşa edilmiş şifre arasında k-Anonymity güvenliğiyle taranacaktır.';
          desc.className = 'text-xs text-mistral-slate mt-1 leading-relaxed';
          document.getElementById('breach-stats').classList.add('hidden');
          const tel = document.getElementById('breach-telemetry');
          if (tel) tel.classList.add('hidden');
        }

        function togglePasswordVisibility() {
          const inp = document.getElementById('input-password');
          const eye = document.getElementById('btn-toggle-eye');
          if (inp.type === 'password') {
            inp.type = 'text';
            eye.innerText = 'Gizle';
          } else {
            inp.type = 'password';
            eye.innerText = 'Göster';
          }
        }

        // 4. Kriptografik Rastgele Parola Üretici
        function generateSecurePassword() {
          const len = parseInt(document.getElementById('gen-length').value) || 18;
          const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
          const lowers = 'abcdefghijklmnopqrstuvwxyz';
          const numbers = '0123456789';
          const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

          let pool = '';
          if (document.getElementById('chk-upper').checked) pool += uppers;
          if (document.getElementById('chk-lower').checked) pool += lowers;
          if (document.getElementById('chk-numbers').checked) pool += numbers;
          if (document.getElementById('chk-symbols').checked) pool += symbols;

          if (!pool) pool = lowers + numbers;

          const randomValues = new Uint32Array(len);
          window.crypto.getRandomValues(randomValues);

          let result = '';
          for (let i = 0; i < len; i++) {
            result += pool[randomValues[i] % pool.length];
          }

          document.getElementById('gen-password-display').innerText = result;
        }

        function copyGeneratedPassword() {
          const pwd = document.getElementById('gen-password-display').innerText.trim();
          if (!pwd || pwd.includes('bekleniyor')) return;
          navigator.clipboard.writeText(pwd).then(() => {
            showToast('✓ Üretilen güçlü parola panoya kopyalandı!');
          });
        }

        function showToast(msg) {
          const toast = document.getElementById('sizinti-toast');
          toast.innerText = msg;
          toast.classList.remove('hidden');
          setTimeout(() => toast.classList.add('hidden'), 3500);
        }

        document.addEventListener('DOMContentLoaded', () => {
          generateSecurePassword();
        });
