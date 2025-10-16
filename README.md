# 🚌 City Card (BinCard) - Akıllı Şehir Ulaşım Sistemi

<div align="center">

![City Card Logo](https://via.placeholder.com/400x200/4CAF50/FFFFFF?text=City+Card)

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7.x-red.svg)](https://redis.io/)
[![JWT](https://img.shields.io/badge/JWT-Authentication-orange.svg)](https://jwt.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Modern şehir ulaşımı için kapsamlı dijital kart ve yönetim sistemi**

[Demo](#demo) • [Kurulum](#kurulum) • [Özellikler](#özellikler) • [API Dokümantasyonu](#api-dokümantasyonu) • [Katkıda Bulunma](#katkıda-bulunma)

</div>

---

## 📋 İçindekiler

- [Proje Hakkında](#proje-hakkında)
- [Temel Özellikler](#temel-özellikler)
- [Teknoloji Stack](#teknoloji-stack)
- [Kurulum](#kurulum)
- [Konfigürasyon](#konfigürasyon)
- [API Dokümantasyonu](#api-dokümantasyonu)
- [Güvenlik Özellikleri](#güvenlik-özellikleri)
- [Modüller](#modüller)
- [Performans](#performans)
- [Deployment](#deployment)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

---

## 🏙️ Proje Hakkında

City Card (BinCard), modern şehir ulaşımı için geliştirilmiş kapsamlı bir dijital kart ve yönetim sistemidir.
Kullanıcıların otobüs kartlarını dijital ortamda yönetebilmeleri, anlık takip yapabilmeleri ve ödeme işlemlerini güvenli
bir şekilde gerçekleştirebilmeleri için tasarlanmıştır.

### 🎯 Hedefler

- **Dijital Dönüşüm**: Geleneksel ulaşım kartlarının dijital ortama taşınması
- **Kullanıcı Deneyimi**: Sezgisel ve kullanıcı dostu arayüz
- **Güvenlik**: Çok katmanlı güvenlik önlemleri ve JWT tabanlı kimlik doğrulama
- **Performans**: Redis cache ve optimizasyonlarla yüksek performans
- **Entegrasyon**: Üçüncü taraf servislerin kesintisiz entegrasyonu

---

## ✨ Temel Özellikler

### 👤 Kullanıcı Yönetimi

- **Çok Faktörlü Kimlik Doğrulama (2FA)**
- **JWT Access/Refresh Token sistemi**
- **IP ve cihaz bazlı erişim kontrolü**
- **Brute force saldırı koruması**
- **Rol tabanlı yetkilendirme (User, Admin, SuperAdmin)**

### 💳 Kart ve Ödeme Sistemi

- **Dijital otobüs kartları**
- **Otomatik bakiye yükleme**
- **İyzico ödeme entegrasyonu**
- **Kart vizeleme sistemi**
- **Cüzdan yönetimi**

### 🚍 Ulaşım Takibi

- **Otobüs anlık takip**
- **Kullanıcı konum takibi**
- **Durak yaklaşım bildirimleri**
- **Rota planlama**
- **GeoIP lokasyon servisleri**

### 🔔 Bildirim Sistemi

- **SMS bildirimleri (Twilio)**
- **Email bildirimleri**
- **Push bildirimleri (Firebase)**
- **Gerçek zamanlı uyarılar**

### 📱 Yönetim ve Raporlama

- **Admin yönetim paneli**
- **SuperAdmin kontrol paneli**
- **Şikayet yönetim sistemi**
- **Geri bildirim toplama**
- **Sürücü sözleşme yönetimi**

### 📁 Dosya Yönetimi

- **Cloudinary entegrasyonu**
- **Fotoğraf ve belge yükleme**
- **Dosya güvenliği ve validasyon**

---

## 🛠️ Teknoloji Stack

### Backend Framework

- **Spring Boot 3.x** - Ana framework
- **Spring Security** - Güvenlik katmanı
- **Spring Data JPA** - Veri erişim katmanı
- **Spring Cache** - Önbellekleme

### Veritabanı

- **PostgreSQL** - Ana veritabanı
- **Redis** - Cache ve session yönetimi
- **HikariCP** - Bağlantı havuzu

### Güvenlik

- **JWT (JSON Web Tokens)** - Kimlik doğrulama
- **BCrypt** - Şifre hashleme
- **Spring Security** - Yetkilendirme

### Entegrasyonlar

- **İyzico** - Ödeme sistemi
- **Twilio** - SMS servisi
- **Firebase** - Push bildirimleri
- **Cloudinary** - Medya yönetimi
- **Google Maps API** - Konum servisleri

### Geliştirme Araçları

- **Swagger/OpenAPI** - API dokümantasyonu
- **Jackson** - JSON işleme
- **Maven** - Dependency yönetimi

---

## 🚀 Kurulum

### Ön Gereksinimler

- Java 21 veya üzeri
- PostgreSQL 14+
- Redis 7.x
- Maven 3.6+

### 1. Projeyi Klonlama

```bash
git clone https://github.com/YusufAkin27/bincard.git
cd bincard


CREATE DATABASE city_card;
CREATE USER postgres WITH PASSWORD '12345';
GRANT ALL PRIVILEGES ON DATABASE city_card TO postgres;

# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis-server

# macOS
brew install redis
brew services start redis

# Docker
docker run -d -p 6379:6379 redis:7-alpine

# .env dosyası oluşturun
cp .env.example .env

# Gerekli değişkenleri ayarlayın
export CLOUDINARY_CLOUD_NAME=your_cloud_name
export CLOUDINARY_API_KEY=your_api_key
export CLOUDINARY_API_SECRET=your_api_secret
export TWILIO_ACCOUNT_SID=your_account_sid
export TWILIO_AUTH_TOKEN=your_auth_token
export TWILIO_PHONE_NUMBER=your_phone_number
export MAIL_USERNAME=your_email
export MAIL_PASSWORD=your_password
export IYZICO_API_KEY=your_iyzico_key
export IYZICO_SECRET_KEY=your_iyzico_secret
export IYZICO_BASE_URL=https://sandbox-api.iyzipay.com
export GOOGLE_MAP_KEY=your_google_maps_key

# Maven ile çalıştırma
./mvnw spring-boot:run

# JAR dosyası oluşturma ve çalıştırma
./mvnw clean package
java -jar target/city-card-1.0.0.jar
