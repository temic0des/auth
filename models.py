from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String
from sqlalchemy import ForeignKey
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
import bcrypt
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120),unique=True, nullable=False, index=True)
    password: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    login_attempts: Mapped[int] = mapped_column(default=0)
    browser_agent: Mapped[str | None] = mapped_column(String(120), nullable=True)
    security_questions: Mapped[list['SecurityQuestion']] = relationship('SecurityQuestion', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def increment_login_attempts(self):
        self.login_attempts += 1
        db.session.commit()

    def reset_login_attempts(self):
        self.login_attempts = 0
        db.session.commit()

    def update_browser_agent(self, agent):
        self.browser_agent = agent
        db.session.commit()

class SecurityQuestion(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    question: Mapped[str] = mapped_column(String(200), nullable=False)
    answer: Mapped[str] = mapped_column(String(200), nullable=False)
    question_number: Mapped[int] = mapped_column(nullable=False)  # 1, 2, or 3

    # user: Mapped["User"] = relationship(back_populates="security_questions")

    def __repr__(self):
        return f'<SecurityQuestion {self.question_number} for User {self.user_id}>'

    @staticmethod
    def encrypt_text(text):
        """Encrypt text using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(text.encode('utf-8'), salt)

    @staticmethod
    def verify_text(text, hashed):
        """Verify text against hashed value"""
        return bcrypt.checkpw(text.encode('utf-8'), hashed)

    def set_question(self, question):
        """Encrypt and set the question"""
        self.question = self.encrypt_text(question)

    def set_answer(self, answer):
        """Encrypt and set the answer"""
        self.answer = self.encrypt_text(answer)

    def verify_answer(self, answer):
        """Verify the answer"""
        return self.verify_text(answer, self.answer)

    @property
    def decrypted_question(self):
        """Return the decrypted question (for display purposes)"""
        return self.question.decode('utf-8') if isinstance(self.question, bytes) else self.question

    @property
    def decrypted_answer(self):
        """Return the decrypted answer (for display purposes)"""
        return self.answer.decode('utf-8') if isinstance(self.answer, bytes) else self.answer 