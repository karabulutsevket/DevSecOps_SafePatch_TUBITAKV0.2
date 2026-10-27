# Sandbox sertleştirme (27 Ekim 2026, Hafta 8)

**Kod:** `safepatch/runner.py` (`sandbox_mode`, `sandboxed`, `Stage`), `scripts/sandbox_check.py`, `samples/hostile/`.
**Testler:** `tests/test_sandbox.py`.
**Ham kanıt:** [`evidence/v02-sandbox/`](../evidence/v02-sandbox/).

Derleme ve testler projenin kodunu çalıştırır. Kötü niyetli ya da bozuk bir proje build sırasında ağa çıkmaya, makinedeki dosyalara uzanmaya ya da makineyi yormaya çalışabilir. Hafta 8'in işi, sandbox ayarlarının yalnız verilmiş değil **etkili** olduğunu göstermek ve bu girişimleri gerçek bir build içinden denemek.

## Değişiklikler

1. **Yerel derleme yalnız geliştirme profilinde.** Runner, sahibi olduğumuz sentetik laboratuvarı da artık yalnız `SAFEPATCH_PROFILE=lab` iken Docker dışında derliyor. Ürün ve değerlendirme profillerinde her iş sandbox'ta çalışır; yerel kip reddedilir (`native_runner_outside_lab_profile`). Runner'ın `/health` yanıtı bunu `native_allowed` ve `usable` alanlarıyla gösteriyor. `start-native.ps1` bu durumda uyarı veriyor.
2. **Kapsayıcıya üç sınır eklendi:**
   - **Takas yok.** `--memory-swap`, belleğe eşit. Docker'ın varsayılanı 2 GB belleğin üstüne 2 GB takas daha veriyordu.
   - **Dosya sınırları.** Tek bir dosya en çok 1 GiB (`fsize`), en çok 8192 açık dosya (`nofile`; önceden yaklaşık 1 milyar), çekirdek dökümü yok (`core=0`).
3. **Çalışma alanının WSL kopyası** (`Stage`). Runner bu kopyayı WSL kullanıcısının yetkisiyle okuyup siliyor; build ise kopyanın içine istediği sembolik bağı bırakabiliyordu. Artık:
   - Rapor ve artifact çekme (`pull`) ve temizleme (`clear`), yolunda sembolik bağ olan bir yolu reddediyor (`sandbox_stage_link_refused`). Önceden `target` bir bağa çevrilirse runner, bağın gösterdiği WSL klasöründen okuyup silebilirdi.
   - "Kaynak değişti mi" denetimi (`changed`) yalnız hâlâ düzenli dosya olan ve bağ üzerinden ulaşılmayan dosyaları okuyor. Bir dosyanın yerine bağ ya da adlandırılmış boru (pipe) konmuşsa açmadan "değişti" sayıyor. Önceden bağın gösterdiği WSL dosyası okunuyordu; boru ise denetimi 10 dakikalık zaman aşımına kadar kilitlerdi.
4. **Çalışma alanları 20 GB'lık ayrı bir dosya sisteminde.** Runner başka yere çalışma alanı koymuyor (aşağıda "Çalışma alanının disk kullanımı").

## Ayarlar, çalışan kapsayıcının içinden

`scripts/sandbox_check.py`, runner'ın kendi komutuyla (`runner.sandboxed`) bir kapsayıcı başlatıyor; kapsayıcı kendi durumunu bildiriyor.

| Ayar | Bayrak | İçeriden okunan |
|---|---|---|
| Ayrı kullanıcı | `--user 1000:1000` | uid 1000, gid 1000 |
| Yetki yok | `--cap-drop ALL` | `CapEff` ve `CapBnd` sıfır |
| Ayrıcalık yükseltme yok | `--security-opt no-new-privileges` | `NoNewPrivs: 1`; seccomp filtre kipinde (`Seccomp: 2`, Docker'ın varsayılan profili) |
| Ağ yok | `--network none` | yalnız `lo` arayüzü |
| Bellek | `--memory 2g --memory-swap 2g` | `memory.max` 2 GiB, `memory.swap.max` 0 |
| İşlemci ve süreç | `--cpus 2 --pids-limit 1024` | `cpu.max` 200000/100000, `pids.max` 1024 |
| Salt okunur kök ve önbellek | `--read-only`, `-v …:/m2:ro` | `/` ve `/m2`'ye yazılamıyor; yalnız `/workspace` yazılabilir |
| Geçici bellek | `--tmpfs /tmp` ve `/jvmtmp` | 1 GiB, `noexec`: oraya konan program çalışmıyor |
| Dosya sınırları | `--ulimit` | `nofile` 8192, `core` 0, `fsize` 1 GiB |
| Disk | çalışma alanı ayrı bir dosya sisteminde | `/workspace` 20 GB'lık kendi dosya sistemi |
| Sırlar | yalnız `HOME` ve `MAVEN_OPTS` verilir | ortamda imajın kendi değişkenlerinden başkası yok; Docker soketi yok |
| Süre | runner'ın zaman aşımı + `docker kill` | aşağıda "Sonsuz bekleme" |
| Çevrimdışı Maven | `mvn -o`, önbellek salt okunur | ağ zaten yok |

## Kötü niyetli build'ler

SQL laboratuvarına kötü niyetli bir JUnit sınıfı ekleniyor (`samples/hostile/`). Sınıf, projenin test takımlarından biri olarak gerçek runner yoluyla (`runner.execute`) sandbox'ta çalışıyor.

Her deneme, başarılı olsa bile zararsız:
- bir genel DNS sunucusuna TCP bağlantısı;
- işaret dosyaları;
- ardından öldürülen uyuyan süreçler;
- öldürülen bir bellek oburu.

Bu vakaların proje tanımı sentetik laboratuvar değil. Bu yüzden runner onları Docker dışında hiç derlemiyor (birim testi var).

| Vaka | Deneme | Sonuç |
|---|---|---|
| `hostile` | ağ arayüzleri, 1.1.1.1:53 ve Docker API'si (172.17.0.1:2375), DNS çözümleme | yalnız `lo`; bağlantı ve çözümleme başarısız |
| | `/`, `/etc`, `/m2`, `/opt`, `/usr/local/bin`, `/workspace/..` altına yazma; `/etc/shadow` okuma | hepsi reddedildi |
| | uid, yetkiler; `mount`, `chroot`, `unshare -Ur` | uid 1000, yetki yok; üçü de başarısız |
| | 2000 süreç başlatma | 1024'ün altında kaldı |
| | sınırsız büyüyen süreç (`tail /dev/zero`) | bellek sınırında öldürüldü (çıkış 137) |
| | `/tmp`'ye 1,1 GB yazma, `/tmp`'den program çalıştırma | dolu; çalıştırılamadı |
| | çalışma alanına 1 GiB'dan büyük tek dosya | reddedildi |
| | **Toplam** | **10 testin 10'u geçti**: her girişim engellendi |
| `tamper` | izlenen bir kaynak dosyanın yerine WSL'de de var olan bir yola bağ, bir test dosyasının yerine boru | iş reddedildi (`tracked_file_changed_during_execution`), saniyeler içinde |
| `link` | `target` klasörünü bir WSL klasörüne bağ yapma | iş reddedildi (`sandbox_stage_link_refused`) |
| `hang` | hiç bitmeyen test | 30 sn sınırında durduruldu, kapsayıcı silindi |

Her vakadan sonra `safepatch-` adlı hiçbir kapsayıcı kalmadı.

**Kontrol.** Aynı kötü niyetli takım bir kez de yalıtım bayrakları olmadan çalıştırıldı: ağ açık, kök yazılabilir, root kullanıcı, yetkiler ve yükseltme açık. Kaynak sınırları korundu. Bu koşuda yalıtımı sınayan **6 testin 6'sı da başarısız oldu**; kaynak sınırlarını sınayan 4 test geçti. Yani sandbox'taki "10/10 geçti" sonucu gerçekten bu ayarlardan geliyor.

**Büyük projeler.** Yeni sınırlarla iki gerçek değerlendirme projesi de önceki sonuçlarını verdi:
- OWASP Benchmark (2 740 servlet): SQL referans düzeltmelerinin 2'si de doğrulandı, gizli testler geçti;
- VUL4J-41 (plexus-archiver): taban geçerli; insan düzeltmesi doğrulandı; kontrol reddedildi; kısmi düzeltme doğrulayıcıyı geçti ama gizli testlere takıldı. Dördü de beklendiği gibi.

Kayıtlar `buyuk-projeler/` altında.

## Çalışma alanının disk kullanımı: ayrı, 20 GB'lık dosya sistemi

**Sorun.** Kapsayıcının çalışma alanı (`/workspace`) WSL diskindeki kopyaya bağlı ve yazılabilir. İlk denetimde bu kopya WSL'in kök dosya sistemindeydi. O disk 1 TB'lık seyrek bir sanal disk (VHDX); fiilen Windows'un C: sürücüsündeki boş alanla sınırlı (bu makinede yaklaşık 70 GB). Kötü niyetli ya da bozuk bir build, çok sayıda büyük dosya yazarak C: sürücüsünü doldurabilirdi. Tek dosya sınırı (1 GiB) bunu durdurmaz. İlk kayıt bu açığı `workspace_disk_bounded: false` olarak gösteriyor (`sandbox/check.json`).

**Karar** (27 Ekim, proje lideri): seçenek A. Diğer seçenekler:
- B, iş başına boyutu sınırlı Docker hacmi: kodun büyük ölçüde yeniden yazılması gerekirdi, her doğrulamaya birkaç saniye eklenirdi;
- C, klasör boyutunu izleyip durdurmak: yarışlı, hızlı bir yazma sınırı aşabilir.

**Kurulum** (WSL'de bir kez, root ile; `scripts/prepare_sandbox.py --bound-work-gb 20`):
- `/var/lib/safepatch/work.img`: 20 GB'lık seyrek ext4 görüntüsü. Bugün diskte yaklaşık 135 MB yer kaplıyor.
- Görüntü `/home/mirror/.safepatch/work` üzerine `loop,nosuid,nodev` ile bağlanıyor. Kökün sahibi runner'ın kullanıcısı.
- Satır `/etc/fstab`'a yazıldı (`nofail`); önceki dosya `/etc/fstab.before-safepatch` olarak saklandı. systemd bağlamayı fstab'dan tanıyor; WSL yeniden başlatılarak denenmedi.
- Betik tekrar çalıştırılırsa hiçbir şey değiştirmiyor.

**Runner artık bunu şart koşuyor.** Çalışma klasörü kendi bağlama noktası değilse çalışma alanını kopyalamıyor; iş `sandbox_work_not_bounded` ile duruyor. Bağlama bir açılışta kurulmazsa da güvenli tarafta kalınıyor.

**Doğrulama** (`disk-sinirli/sandbox/check.json`, ürün kodu `77615b6`; kayıttaki `git_dirty` yalnız henüz commit'lenmemiş belgelerden): yoklama artık gerçek bir çalışma alanı klasöründe çalışıyor. Kapsayıcının gördüğü `/workspace` 20 GB'lık bu dosya sistemi; denetimlerin 15'i de tutuyor. Kötü niyetli vakaların ve kontrolün sonuçları ilk kayıtla aynı. Bir build en çok bu 20 GB'ı doldurabilir. Testler: `-Sandbox` ile 619 geçti (`disk-sinirli/testler/`).

**Linux sunucuda** aynı şart, ayrı bir bölüm ya da mantıksal birimle karşılanır; XFS proje kotası da olur, ama runner bugün ayrı bağlama noktası arıyor.

## Sınırlar

- **Runner'ın kendisi kısıtlı değil.** Runner, Docker'ı kullanıcının `docker` grubu üzerinden çağırıyor; bu grup fiilen root eşdeğeridir. Sandbox proje kodunu sınırlar, runner'ı değil. Runner güvenilir koddur (CLAUDE.md, kural 1).
- **Kullanıcı adları eşleniyor.** Docker'da kullanıcı adı alanı eşlemesi (`userns-remap`) açık değil: kapsayıcıdaki uid 1000, WSL'deki kullanıcıyla aynı. Yetkisiz ve yükseltmesiz olduğu için kapsayıcıdan kaçan bir süreç root değil, bu kullanıcı olur. Eşleme bir Docker sunucusu ayarı; ileride düşünülebilir.
- **Ek profil yok.** Docker'ın varsayılan seccomp profili kullanılıyor; WSL'de AppArmor ya da SELinux profili yok.
- **Loopback açık.** Testler kendi yerel sunucularını kullanabilir (OWASP Benchmark'ın HSQLDB sunucusu gibi); dışarıya çıkış yok.
- **Compose taslağı.** Compose'daki runner kapsayıcısı ürün profilinde artık yerel derleme yapamaz. Compose kurulumunda sandbox tasarımı ayrıca ele alınmalı (Hafta 10, kurulum paketi).
- **Yerel kipte çalışan betikler.** Bazı geliştirme betikleri sentetik vakaları yerel derliyor (ör. `variants_dev.py --check`, `faz1_exit.py`'nin servisleri). Bunlar artık `SAFEPATCH_PROFILE=lab` ister; aksi halde iş açık bir hatayla reddedilir.
