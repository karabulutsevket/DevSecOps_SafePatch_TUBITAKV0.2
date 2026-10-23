# SafePatch — 12 Haftalık Ürün Geliştirme Roadmap'i

> **Versiyon:** 1.0  
> **Başlangıç:** Hafta 1  
> **Bitiş:** Hafta 12  
> **Hedef:** TÜBİTAK BiGG pilot görüşmesine hazır, air-gapped çalışan, ölçülebilir Ar-Ge hipotezine sahip MVP  
> **Geliştirici:** 1 kişi + Claude (yardımcı)  
> **Ana Ar-Ge Hipotezi:** Kanıt ağırlıklı Verified Fix Memory (EW-VFM), naif RAG ve hafızasız LLM'e kıyasla güvenli onarım başarısını anlamlı ölçüde artırır.

---

## 0. Doküman Bilgisi

| Alan | Değer |
|---|---|
| Proje Adı | SafePatch |
| Proje Tipi | Air-gapped DevSecOps / Otonom Zafiyet Düzeltme Platformu |
| MVP Kapsamı | SAST (Semgrep) + SCA (Trivy) + EW-VFM + Yerel LLM + 3 Aşamalı Doğrulama |
| Kapsam Dışı | DAST, IAST, SaaS, Kubernetes, Mikroservis, Fine-tuning |
| Hedef Müşteri | Savunma sanayii + finans (air-gapped) |
| Çalışma Modeli | Tek sunucu, Docker Compose, offline |

---

## 1. Misyon ve Kapsam

### 1.1. Misyon
> Air-gapped ortamlarda çalışan kurumların, SAST ve SCA bulgularını **kurumsal hafızadan** ve **yerel LLM'den** yararlanarak, **denetlenebilir ve kanıtlanabilir** şekilde otomatik düzeltmesini sağlamak.

### 1.2. MVP Kapsamı (İçeride)

- ✅ **Semgrep** (SAST) entegrasyonu — birincil tarayıcı
- ✅ **Trivy** (SCA) entegrasyonu — ikincil tarayıcı
- ✅ **Bulgu normalizasyonu** — ortak şema (SARIF + JSON → `Finding`)
- ✅ **Verified Fix Memory (VFM)** — PostgreSQL + pgvector
- ✅ **Kanıt ağırlıklı sıralama** — çok boyutlu skor
- ✅ **Yerel LLM** — DeepSeek-Coder-7B veya Qwen2.5-Coder-7B (Ollama)
- ✅ **3 aşamalı doğrulama** — AST → Docker sandbox → yeniden tarama
- ✅ **Hata sınıflandırmalı retry** — 1-3 arası dinamik
- ✅ **İnsan onayı** — CLI + minimal web
- ✅ **Audit log** — append-only
- ✅ **Air-gapped kurulum** — Docker Compose, tek komut
- ✅ **Benchmark** — 3 grup × 30 örnek

### 1.3. Kapsam Dışı (Dışarıda — Sonraki Sürümler)

- ❌ DAST (OWASP ZAP)
- ❌ IAST
- ❌ Kubernetes / mikroservis
- ❌ SaaS / çok kiracılı bulut
- ❌ Fine-tuning
- ❌ Otomatik production deploy
- ❌ 5+ dil (MVP: yalnızca Python)
- ❌ 3+ framework (MVP: yalnızca Django + Flask)

> ⚠️ **KAPSAM KURALI:** Bu dosyadaki "Kapsam Dışı" maddelerinden herhangi biri için **istek gelirse reddedin**. Kapsam genişlemesi, 12 haftalık planın en büyük düşmanıdır.

---

## 2. Proje Başarı Kriterleri (Definition of Done)

Aşağıdakilerin **tamamı** sağlanmadan proje "bitti" sayılmaz:

- [ ] Tek komutla (`docker compose up`) air-gapped ortamda çalışıyor
- [ ] Semgrep, en az 1 gerçek Python projesinde taranıyor
- [ ] Trivy, en az 1 `requirements.txt` dosyasında CVE buluyor
- [ ] Bulgu normalizasyonu 2 tarayıcıdan gelen çıktıyı aynı şemada birleştiriyor
- [ ] VFM'ye en az 10 kayıt eklenmiş ve vektör aramayla getirilebiliyor
- [ ] LLM, en az 1 CWE-89 (SQL Injection) bulgusunu düzeltiyor
- [ ] AST doğrulaması başarısız yamaları test öncesi reddediyor
- [ ] Docker sandbox'ta test çalışıyor ve sonuç dönüyor
- [ ] Yeniden tarama, zafiyetin kapandığını doğruluyor
- [ ] 3 retry döngüsü hataya göre strateji değiştiriyor
- [ ] Audit log, her adımı kaydediyor
- [ ] Benchmark: 3 grup × 30 örnek × 3 tekrar = 270 deney tamamlandı
- [ ] Benchmark sonuçları `benchmark/results.md`'de raporlandı
- [ ] Ana hipotez: Grup C > Grup B > Grup A (yönlü olarak en az 1 metrikte)
- [ ] Kurulum kılavuzu ile temiz bir ortamda sistem 30 dakikada ayağa kalkıyor
- [ ] Air-gapped testi: egress engelli, model dışarı veri göndermiyor
- [ ] Güvenlik kontrol listesi (Bölüm 8) tamamen işaretli
- [ ] Pilot sunumu + demo senaryosu hazır
- [ ] En az 3 potansiyel müşteri görüşmesi yapıldı

---

## 3. Tech Stack

| Katman | Teknoloji | Versiyon | Gerekçe |
|---|---|---|---|
| **Dil** | Python | 3.11+ | Ekosistem, LLM entegrasyonu |
| **Web Framework** | FastAPI | 0.109+ | Async, hızlı, otomatik dokümantasyon |
| **Görev Kuyruğu** | Celery + Redis | 5.3+ / 7+ | Uzun işler için asenkron |
| **Veritabanı** | PostgreSQL + pgvector | 16+ / 0.7+ | Tek DB, vektör + ilişkisel |
| **LLM Runtime** | Ollama | latest | Basit, offline model yönetimi |
| **LLM Modeli** | DeepSeek-Coder-7B veya Qwen2.5-Coder-7B | — | Python kod üretimi, 7B sığar |
| **SAST** | Semgrep | latest | Hızlı, SARIF, offline |
| **SCA** | Trivy | latest | SBOM + CVE, JSON |
| **AST** | tree-sitter | 0.21+ | Çoklu dil parser |
| **Sandbox** | Docker | 24+ | İzolasyon |
| **Frontend (MVP)** | HTMX + Alpine.js | — | Basit, hafif; React gereksiz |
| **Auth** | JWT (python-jose) | — | Standart |
| **Audit Log** | PostgreSQL (append-only) | — | MVP için yeterli |
| **Test** | pytest | 8+ | Standart |

**Kurulum ortamı:** Debian 12/Ubuntu 22.04 LTS, min 16GB RAM, 4 CPU, 50GB disk (LLM modeli dahil).

---

## 4. Mimari Özet

```mermaid
flowchart LR
    U[Kullanıcı: CLI/Web] --> API[FastAPI]
    API --> Q[Celery + Redis]
    Q --> AD[Adaptörler<br/>Semgrep, Trivy]
    AD --> NORM[Normalizasyon]
    NORM --> VFM[(PostgreSQL + pgvector)]
    VFM --> RET[Retrieval & Sıralama]
    RET --> LLM[Ollama: DeepSeek-7B]
    LLM --> AST[AST Doğrulama]
    AST --> SB[Docker Sandbox]
    SB --> RESCAN[Yeniden Tarama]
    RESCAN -->|Başarılı| VFM
    RESCAN -->|Başarısız| LLM
    VFM --> AUDIT[Audit Log]
    AUDIT --> U