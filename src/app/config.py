from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    DEBUG: bool = True
    # For CORS
    ALLOWED_ORIGINS: list = ["*"]  # allow all for dev/demo; change later in prod

    HOST: str = "localhost"
    PORT: int = 8000
    # Optional: build DATABASE_URL from parts
    @property
    def DATABASE_URL(self):
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    class Config:
        env_file = ".env"
settings = Settings()
