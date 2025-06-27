# MyData API Operator - Enhanced Bank Services with Local Security

## Overview

This repository implements the **MyData Operator** component of the MyData API ecosystem, serving as an advanced bank API service that provides account information with **built-in local intrusion detection capabilities**. The system is both protected by and contributes to the **Certification Authority's centralized security monitoring** while maintaining independent threat detection.

## System Architecture

The MyData Operator is part of the three-component MyData ecosystem with enhanced security:

- **🔐 Certification Authority** - Central authentication and security monitoring
- **🏦 Information Provider** - Bank API services for account information
- **🏛️ MyData Operator** (this system) - Enhanced bank services + local intrusion detection

## 🏦 Core Banking Services

### Account Information APIs

The MyData Operator provides comprehensive banking services through MyData-compliant APIs:

- **Basic Account Information** - Account metadata, currency, and basic details
- **Detailed Account Information** - Transaction history, balance details, and account status
- **Deposit Account Services** - Savings account information and deposit details
- **Enhanced Security Monitoring** - Real-time threat detection on all transactions

### Dual Security Architecture

- **Centralized Security** - Integrates with Certification Authority's monitoring
- **Local Detection** - Independent intrusion detection algorithms
- **Hybrid Monitoring** - Combined approach for maximum threat coverage
- **Real-time Analysis** - Immediate threat response and logging

## 🛡️ Local Intrusion Detection System

### Multi-Algorithm Detection Engine

The MyData Operator includes its own detection capabilities:

1. **Signature-Based Detection**

   - Local pattern matching for known attack signatures
   - SQL injection, XSS, and command injection detection
   - Real-time threat identification

2. **Specification-Based Detection**

   - API request/response validation against local schemas
   - Parameter tampering and data manipulation detection
   - Zod-based validation framework

3. **Hybrid Detection**

   - Combines signature and specification detection
   - Optimized for banking transaction security
   - Performance-tuned for high-volume processing

4. **Local Analysis Engine**
   - Security log analysis and correlation
   - Attack pattern recognition
   - Performance metrics and reporting

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm
- PostgreSQL database
- Access to Certification Authority (port 3000)

### Installation

1. **Clone and setup**

   ```bash
   cd mydata-operator-next
   npm install
   ```

2. **Environment Configuration**

   ```bash
   # Copy environment template
   cp .env.example .env

   # Configure database and integration settings
   DATABASE_URL="postgresql://user:password@localhost:5432/mydata_operator_db"
   CERTIFICATION_AUTHORITY_URL="http://localhost:3000"
   ANYA_CLIENT_ID="your-client-id"
   ANYA_CLIENT_SECRET="your-client-secret"
   ANYA_ORG_CODE="your-org-code"
   ```

3. **Database Setup**

   ```bash
   # Run database migrations
   npx prisma migrate dev

   # Seed account data
   npm run seedAccount
   ```

4. **Start the service**

   ```bash
   npm run dev
   ```

   The MyData Operator will be available at: `http://localhost:4200`

## 🔗 API Endpoints

### Bank Account Services

#### Basic Account Information

```
POST /api/v2/bank/accounts/deposit/basic
```

- **Authentication**: Bearer token from Certification Authority
- **Security**: Local + centralized intrusion detection
- **Response**: Account currency, saving method, dates, and amounts

#### Detailed Account Information

```
POST /api/v2/bank/accounts/deposit/detail
```

- **Authentication**: Bearer token from Certification Authority
- **Security**: Enhanced validation and monitoring
- **Response**: Comprehensive account data with transaction history

### Authentication Integration

```
POST /api/oauth/2.0/token
```

- **Purpose**: OAuth token endpoint for bank-to-bank authentication
- **Integration**: Validates certificates from Certification Authority
- **Security**: Local token validation and threat detection

## 🔍 Local Security Operations

### Running Detection Algorithms

```bash
# Local signature-based detection
npm run signature

# Local specification-based detection
npm run specification

# Local hybrid detection (recommended)
npm run hybrid

# Comprehensive security analysis
npm run analysis
```

### Attack Detection & Response

```bash
# Real-time attack detection
npm run detect

# Security log analysis
npm run analysis
```

## 🧪 Testing & Security Validation

### Normal Operation Testing

```bash
# Standard MyData flow simulation
npm run simulate

# Account data simulation
npm run seedAccount
```

### Security Testing

```bash
# Attack simulation for local detection testing
npm run attack

# Detection algorithm validation
npm run hybrid
npm run specification
npm run signature
```

### Complete MyData Flow Testing

The system supports full MyData ecosystem testing:

1. **IA101** - Token request to Certification Authority
2. **IA102** - Certificate signing request with local validation
3. **IA103** - Certificate signing result verification
4. **IA104** - Certificate verification with threat detection
5. **IA002** - Bank-to-bank authentication with monitoring
6. **Account Data Retrieval** - Secure access with dual security layers

## 🛡️ Dual Security Integration

### Certification Authority Integration

- **Token Validation** - JWT tokens validated through CA
- **Centralized Logging** - Security events reported to CA dashboard
- **Threat Correlation** - Local threats correlated with ecosystem-wide patterns
- **Certificate Management** - Digital certificate validation

### Local Security Capabilities

- **Independent Detection** - Local threat detection without CA dependency
- **Real-time Response** - Immediate threat mitigation
- **Performance Optimization** - Banking-specific security tuning
- **Custom Rules** - Bank-specific security patterns

## 📊 Enhanced Data Models

### Account Information with Security Context

```typescript
interface SecureAccount {
	accountNum: string; // Unique account identifier
	accountStatus: string; // Account status with validation
	accountType: string; // Account type with security checks
	firstName: string; // Validated account holder first name
	lastName: string; // Validated account holder last name
	orgCode: string; // Organization code with validation
	phoneNumber: string; // Validated contact information
	balanceAmt: number; // Balance with integrity checks
	currencyCode: string; // Currency with format validation
	securityContext: {
		// Enhanced security information
		lastValidated: Date;
		threatLevel: string;
		accessPattern: string;
	};
}
```

### Security Event Logging

```typescript
interface SecurityEvent {
	eventId: string; // Unique event identifier
	timestamp: Date; // Event timestamp
	detectionType: string; // Local detection method used
	threatLevel: string; // Assessed threat level
	accountNum?: string; // Associated account (if applicable)
	attackPattern: string; // Detected attack pattern
	responseAction: string; // Automated response taken
	reportedToCA: boolean; // Whether event was reported centrally
}
```

## 🔧 Configuration

### Environment Variables

```env
# Database Configuration
DATABASE_URL="postgresql://localhost:5432/mydata_operator"
DIRECT_URL="postgresql://localhost:5432/mydata_operator"

# Integration Settings
CERTIFICATION_AUTHORITY_URL="http://localhost:3000"
ANYA_BANK_API="http://localhost:4000"  # Information Provider URL

# Organization Credentials
ANYA_CLIENT_ID="your-client-id"
ANYA_CLIENT_SECRET="your-client-secret"
ANYA_ORG_CODE="your-organization-code"
ANYA_ORG_SERIAL_CODE="your-serial-code"

# Security Settings
JWT_SECRET="your-jwt-secret"
LOCAL_DETECTION_ENABLED="true"
THREAT_RESPONSE_LEVEL="medium"
```

### Security Configuration

```typescript
// Local detection settings
interface SecurityConfig {
	enableSignatureDetection: boolean;
	enableSpecificationDetection: boolean;
	enableHybridDetection: boolean;
	threatResponseLevel: 'low' | 'medium' | 'high';
	reportToCentralAuthority: boolean;
	localAnalysisEnabled: boolean;
}
```

## 📈 Security Analytics & Monitoring

### Local Security Dashboard

The MyData Operator provides local security insights:

- **Real-time Threat Detection** - Live monitoring of API requests
- **Attack Pattern Analysis** - Local pattern recognition and trending
- **Performance Metrics** - Detection algorithm performance
- **Response Time Analysis** - Security response effectiveness

### Integration with CA Security Dashboard

- **Threat Correlation** - Local threats correlated with ecosystem patterns
- **Centralized Reporting** - Security events reported to CA dashboard
- **Ecosystem Intelligence** - Benefits from CA's comprehensive threat intelligence
- **Coordinated Response** - Participates in ecosystem-wide security responses

## 🐳 Docker Deployment

```bash
# Build container with security features
docker build -t mydata-operator-enhanced .

# Run with security configuration
docker run -p 4200:4200 \
  -e DATABASE_URL="your-db-url" \
  -e CERTIFICATION_AUTHORITY_URL="http://ca:3000" \
  -e LOCAL_DETECTION_ENABLED="true" \
  mydata-operator-enhanced
```

## 📁 Enhanced Project Structure

```
mydata-operator-next/
├── app/
│   ├── (routes)/account/mydata/    # MyData account pages
│   ├── _components/                # UI components
│   ├── _providers/                 # React providers
│   └── api/                        # Enhanced bank API endpoints
├── constants/                      # Response messages and bank data
├── hooks/                         # React hooks for data fetching
├── prisma/                        # Database schema with security models
├── scripts/                       # Detection algorithms and simulations
│   ├── detectionSignature.ts      # Local signature detection
│   ├── detectionSpecification.ts  # Local specification detection
│   ├── detectionHybrid.ts         # Local hybrid detection
│   └── analysis.ts                # Local security analysis
├── types/                         # TypeScript type definitions
└── utils/                         # Enhanced security utilities
```

## 🛠️ Development & Customization

### Adding New Security Rules

1. **Signature Detection** - Add patterns to local detection engine
2. **Specification Rules** - Update local validation schemas
3. **Threat Response** - Customize automated response actions
4. **Reporting Integration** - Configure CA reporting parameters

### Testing Security Features

```bash
# Test local detection algorithms
npm run signature
npm run specification
npm run hybrid

# Test integrated security (local + CA)
npm run detect

# Analyze security performance
npm run analysis
```

## 🤝 Advanced Ecosystem Integration

### Multi-layered Security Architecture

1. **Local Detection Layer** - Immediate threat detection and response
2. **Certification Authority Layer** - Ecosystem-wide threat correlation
3. **Cross-Bank Intelligence** - Shared threat intelligence with Information Provider
4. **Coordinated Response** - Synchronized security responses across ecosystem

### Enhanced MyData Compliance

- **Advanced API Security** - Enhanced security beyond standard MyData requirements
- **Proactive Threat Detection** - Predictive security measures
- **Compliance Monitoring** - Automated compliance validation
- **Security Audit Trail** - Comprehensive security logging

## 🔍 Advanced Troubleshooting

### Security-Specific Issues

1. **Local Detection Performance**

   - Monitor detection algorithm performance
   - Tune security rules for optimal response times
   - Balance security vs. performance

2. **CA Integration Problems**

   - Verify dual reporting mechanisms
   - Check network connectivity for security data
   - Validate security event correlation

3. **Threat Response Issues**
   - Review automated response configurations
   - Test threat mitigation effectiveness
   - Validate escalation procedures

## 📚 Advanced Security Documentation

### Local Detection API

```javascript
// Local threat detection
const detectThreat = async (request) => {
	const signatureResult = await runSignatureDetection(request);
	const specificationResult = await runSpecificationDetection(request);
	const hybridResult = await runHybridDetection(request);

	return {
		localThreatDetected: hybridResult.detected,
		reportedToCA: true,
		responseAction: 'block' | 'monitor' | 'allow',
	};
};
```

### Security Event Format

```json
{
  "eventId": "evt-123456789",
  "timestamp": "2024-01-01T12:00:00Z",
  "source": "mydata-operator-local",
  "detectionType": "hybrid",
  "threatLevel": "medium",
  "accountContext": {...},
  "attackVector": "parameter-tampering",
  "responseAction": "blocked",
  "reportedToCA": true,
  "correlationId": "ca-corr-987654321"
}
```

---

**Enhanced Security Notice**: This MyData Operator provides dual-layer security with both local intrusion detection and centralized monitoring. The combination ensures maximum protection for banking transactions while maintaining optimal performance and compliance with MyData ecosystem standards.
