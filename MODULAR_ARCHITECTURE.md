# Modular Architecture Plan

## Current State Analysis

The current `main.go` is a monolithic file (~2000+ lines) containing:
- Configuration management
- Certificate processing logic
- Metrics collection
- HTTP server and API handlers
- File system watching
- Cache management
- Health checks
- Logging setup
- Global state management

## Target Modular Architecture

### Package Structure

```
cert-monitor/
├── cmd/
│   └── cert-monitor/
│       └── main.go              # Slim main, orchestration only
├── internal/
│   ├── config/
│   │   ├── config.go            # Configuration types and loading
│   │   ├── validation.go        # Configuration validation
│   │   └── reload.go            # Hot reload functionality
│   ├── certificate/
│   │   ├── processor.go         # Certificate processing logic
│   │   ├── parser.go            # Certificate parsing (PEM, DER, etc.)
│   │   ├── analyzer.go          # Crypto analysis (weak keys, etc.)
│   │   ├── scanner.go           # Directory scanning
│   │   └── types.go             # Certificate-related types
│   ├── metrics/
│   │   ├── collector.go         # Prometheus metrics collection
│   │   ├── registry.go          # Metrics registration
│   │   └── types.go             # Metrics types and definitions
│   ├── cache/
│   │   ├── manager.go           # Cache management
│   │   ├── storage.go           # Cache storage (file, memory)
│   │   └── types.go             # Cache-related types
│   ├── watcher/
│   │   ├── filesystem.go        # File system watching
│   │   ├── config.go            # Configuration file watching
│   │   └── types.go             # Watcher types
│   ├── server/
│   │   ├── server.go            # HTTP server setup
│   │   ├── handlers.go          # API handlers
│   │   ├── health.go            # Health check handlers
│   │   ├── middleware.go        # HTTP middleware
│   │   └── routes.go            # Route definitions
│   ├── worker/
│   │   ├── pool.go              # Worker pool management
│   │   ├── processor.go         # Worker processing logic
│   │   └── types.go             # Worker types
│   └── state/
│       ├── global.go            # Global state management
│       ├── backoff.go           # Scan backoff logic
│       └── types.go             # State types
├── pkg/
│   ├── logger/
│   │   └── logger.go            # Logging utilities
│   └── utils/
│       ├── crypto.go            # Cryptographic utilities
│       ├── filesystem.go        # File system utilities
│       └── validation.go        # Common validation functions
└── test/
    ├── integration/             # Integration tests
    ├── fixtures/               # Test data and certificates
    └── mocks/                  # Mock implementations
```

## Design Principles

### 1. Separation of Concerns
- **Each package has a single responsibility**
- **Clear interfaces between packages**
- **No circular dependencies**

### 2. Dependency Injection
- **Interfaces for external dependencies**
- **Easy testing and mocking**
- **Configurable implementations**

### 3. Error Handling
- **Consistent error types across packages**
- **Proper error wrapping and context**
- **Graceful degradation**

### 4. Testability
- **Each package is independently testable**
- **Mock interfaces for dependencies**
- **Table-driven tests where appropriate**

## Package Responsibilities

### cmd/cert-monitor/main.go
```go
// Slim main function - orchestration only
func main() {
    // Parse flags and config
    // Initialize dependencies
    // Start services
    // Handle shutdown
}
```

### internal/config/
**Purpose**: Configuration management and validation
**Responsibilities**:
- Load configuration from files, environment, CLI
- Validate configuration values
- Hot reload configuration changes
- Provide configuration to other packages

**Key interfaces**:
```go
type Manager interface {
    Load(path string) (*Config, error)
    Reload() error
    Watch(ctx context.Context) <-chan *Config
    Validate(*Config) error
}
```

### internal/certificate/
**Purpose**: Certificate processing and analysis
**Responsibilities**:
- Parse certificate files (PEM, DER, PFX, P7B)
- Analyze cryptographic strength
- Extract certificate metadata
- Scan directories for certificates

**Key interfaces**:
```go
type Processor interface {
    ProcessDirectory(ctx context.Context, path string) ([]Certificate, error)
    ParseFile(path string) (*Certificate, error)
    AnalyzeSecurity(*Certificate) SecurityInfo
}

type Scanner interface {
    Scan(ctx context.Context, dirs []string) <-chan ScanResult
}
```

### internal/metrics/
**Purpose**: Prometheus metrics collection and management
**Responsibilities**:
- Define and register Prometheus metrics
- Update metrics based on certificate data
- Provide metrics HTTP handler
- Reset and manage metric lifecycle

**Key interfaces**:
```go
type Collector interface {
    UpdateCertificate(cert *Certificate)
    UpdateScanMetrics(duration time.Duration, errors int)
    Reset()
    Handler() http.Handler
}
```

### internal/cache/
**Purpose**: Certificate caching for performance
**Responsibilities**:
- Cache certificate metadata
- Implement cache storage (file-based, in-memory)
- Cache invalidation and pruning
- Cache statistics

**Key interfaces**:
```go
type Manager interface {
    Get(path string) (*CertificateMeta, bool)
    Set(path string, meta *CertificateMeta)
    Delete(path string)
    Prune() int
    Stats() Statistics
}
```

### internal/server/
**Purpose**: HTTP server and API endpoints
**Responsibilities**:
- HTTP server setup and configuration
- API route handling
- Health checks
- Middleware (logging, metrics, etc.)

**Key interfaces**:
```go
type Server interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    RegisterHandlers(handlers ...Handler)
}
```

### internal/watcher/
**Purpose**: File system and configuration watching
**Responsibilities**:
- Watch certificate directories for changes
- Watch configuration file for changes
- Debounce and filter events
- Trigger appropriate responses

**Key interfaces**:
```go
type Watcher interface {
    Watch(ctx context.Context, paths []string) <-chan Event
    Add(path string) error
    Remove(path string) error
}
```

## Migration Strategy

### Phase 1: Package Structure (Week 1)
1. **Create package directories** and basic structure
2. **Extract types and constants** into appropriate packages
3. **Move simple utilities** (crypto helpers, validation)
4. **Ensure compilation** with minimal changes

### Phase 2: Core Logic Extraction (Week 2)
1. **Extract configuration management** to `internal/config/`
2. **Move certificate processing** to `internal/certificate/`
3. **Separate metrics logic** to `internal/metrics/`
4. **Update main.go** to use new packages

### Phase 3: Advanced Components (Week 3)
1. **Extract cache management** to `internal/cache/`
2. **Move HTTP server logic** to `internal/server/`
3. **Separate file watching** to `internal/watcher/`
4. **Create worker pool package** in `internal/worker/`

### Phase 4: Testing and Documentation (Week 4)
1. **Add comprehensive unit tests** for each package
2. **Create integration tests** for package interactions
3. **Update documentation** and examples
4. **Performance testing** and optimization

## Benefits of Modular Design

### 1. Maintainability
- **Easier to understand** individual components
- **Simpler to modify** specific functionality
- **Reduced risk** of unintended side effects

### 2. Testability
- **Unit tests** for individual packages
- **Mock interfaces** for dependencies
- **Integration tests** for package interactions

### 3. Reusability
- **Packages can be reused** in other projects
- **Clear interfaces** make components interchangeable
- **Standard Go package conventions**

### 4. Development Velocity
- **Multiple developers** can work on different packages
- **Parallel development** of features
- **Easier code reviews** with smaller, focused changes

### 5. Performance
- **Lazy loading** of components
- **Configurable implementations** based on needs
- **Better resource management**

## Implementation Guidelines

### 1. Interface Design
```go
// Good: Small, focused interfaces
type Parser interface {
    Parse(data []byte) (*Certificate, error)
}

// Avoid: Large, monolithic interfaces
type EverythingManager interface {
    Parse(...) 
    Cache(...)
    Watch(...)
    Serve(...)
}
```

### 2. Error Handling
```go
// Define package-specific error types
type ValidationError struct {
    Field string
    Value interface{}
    Reason string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation failed for field %s: %s", e.Field, e.Reason)
}
```

### 3. Configuration
```go
// Each package defines its own config struct
type ServerConfig struct {
    Port        string
    BindAddress string
    TLSCert     string
    TLSKey      string
}

// Main config composes package configs
type Config struct {
    Server      ServerConfig
    Certificate CertificateConfig
    Cache       CacheConfig
    // ...
}
```

### 4. Testing Strategy
```go
// Use interfaces for testing
type MockProcessor struct {
    ProcessFunc func(ctx context.Context, path string) ([]Certificate, error)
}

func (m *MockProcessor) ProcessDirectory(ctx context.Context, path string) ([]Certificate, error) {
    if m.ProcessFunc != nil {
        return m.ProcessFunc(ctx, path)
    }
    return nil, nil
}
```

## Success Criteria

### Functional Requirements
- [ ] All existing functionality preserved
- [ ] No breaking changes to external APIs
- [ ] Performance maintained or improved
- [ ] Configuration compatibility maintained

### Code Quality Requirements
- [ ] Each package has < 500 lines of code
- [ ] 80%+ test coverage for each package
- [ ] No circular dependencies
- [ ] Clear package documentation
- [ ] Consistent error handling

### Development Experience
- [ ] Faster build times for incremental changes
- [ ] Easier to add new features
- [ ] Simpler debugging and troubleshooting
- [ ] Better IDE support (go to definition, etc.)

This modular architecture will transform cert-monitor from a monolithic application into a well-structured, maintainable Go project following industry best practices.