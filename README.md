# SecretGuard

Python standart kütüphanesiyle çalışan hafif bir CLI hassas veri tarayıcısı.

## Özellikler

- Belirtilen klasörü alt klasörleriyle birlikte tarar; gizli dosyaları da inceler.
- Regex ile API key, AWS access key, GitHub token, Bearer token, parola ve private key başlangıçlarını arar.
- `api_key`, `token`, `password`, `client_secret` gibi alanların `=` veya `:` ile yapılan atamalarını kontrol eder.
- Dosya adını, 1'den başlayan satır numarasını ve bulgu türünü gösterir. Aynı satırdaki aynı tür tek bulgu olarak raporlanır.
- Hassas değerleri terminalde ve JSON raporunda tamamen `********` ile maskeler; kaynak satırını rapora eklemez.
- `.git` klasörlerini, `.git` dosyalarını ve sembolik bağlantıları atlar.
- NUL/kontrol baytı içeren veya UTF-8 olarak çözülemeyen dosyaları binary kabul ederek atlar.
- Okuma hatalarını bildirir ve diğer dosyaları taramaya devam eder.
- Harici bağımlılık gerektirmez.

## Kurulum

Python 3.8 veya üzeri gerekir. `secretguard.py` dosyasını bilgisayarınıza kopyalayın; paket kurulumu gerekmez.

```console
python --version
python secretguard.py --help
```

Windows'ta `python` yerine `py` kullanılabilir.

## Kullanım

Geçerli klasörü veya belirli bir klasörü tarayın:

```console
python secretguard.py
python secretguard.py ./projem
python secretguard.py "C:\Projeler\Uygulamam"
```

Örnek terminal çıktısı:

```text
"config.env":3 | API key | ********
"settings.py":12 | Parola | ********
2 olası hassas veri bulundu.
```

JSON raporunu terminale yazdırın veya dosyaya yönlendirin. Rapor dosyasını taranan klasörün dışında tutun; kabuk yönlendirmesi dosyayı tarama başlamadan oluşturabilir.

```console
python secretguard.py ./projem --json
python secretguard.py ./projem --json > secretguard-report.json
```

JSON yapısı:

```json
{
  "findings": [
    {"file": "config.env", "line": 3, "type": "API key", "value": "********"}
  ],
  "errors": []
}
```

Çıkış kodları: `0` bulgu yok, `1` en az bir bulgu var, `2` kullanım veya okuma hatası var. Okuma hatası olduğunda rapor kısmi olabilir; bulunan kayıtlar yine gösterilir. Geçersiz kullanım hataları standart hata çıktısına yazılır.

## Sınırlar

Regex eşleşmeleri olası sızıntıları gösterir; anahtarların geçerliliğini doğrulamaz. Örnek değerler ve yorumlar da eşleşebilir. Şifrelenmiş, kodlanmış, parçalanmış veya farklı adlarla tutulan hassas veriler kaçabilir. Private key kontrolü başlangıç işaretini bildirir; anahtar gövdesini ayrıştırmaz.

Metin taraması UTF-8 ile sınırlıdır. Binary kontrolü sezgiseldir; bazı binary dosyalar metin gibi görünebilir. Dosyalar tek tek belleğe alınır; çok büyük dosyalar bellek tüketimini artırır. Araç dosyaları değiştirmez ve ağ bağlantısı kurmaz. Raporlar dosya adlarını içerir.
