from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    DEBUG: bool = True
    # For CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "https://z62vgvqj-8000.inc1.devtunnels.ms"
    ]

    HOST: str = "localhost"
    PORT: int = 8000
    #JWT config
    JWT_SECRET_KEY: str  #random hex,in .env,64 char hex(32 bytes)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = 8
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_DIGITS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = False
    @property
    def DATABASE_URL(self):
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    class Config:
        env_file = ".env"
settings = Settings()
