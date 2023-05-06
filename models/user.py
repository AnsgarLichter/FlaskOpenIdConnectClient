from database import db
from flask_login import UserMixin
from hash import flask_bcrypt


class User(db.Model, UserMixin):
    # TODO: Revert back to auto incremented ID instead of sub from oidc provider
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)

    connected_providers = db.relationship(
        "ConnectedOidcProvider",
        lazy="dynamic",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    local_account = db.relationship(
        "LocalUser",
        lazy="dynamic",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    @classmethod
    def create_local_user(cls, username, password):
        instance = cls(username=username)
        db.session.add(instance)

        LocalUser.create(instance, password)

        return instance

    @classmethod
    def create_oidc_account(cls, username, provider, sub):
        instance = cls(username=username)
        db.session.add(instance)

        ConnectedOidcProvider.create(
            instance,
            provider,
            sub
        )

        return instance

    def connect_oidc_provider(self, provider, sub):
        ConnectedOidcProvider.create(
            self,
            provider,
            sub
        )

    def disconnect_oidc_provider(self, provider):
        connected_provider = self.connected_providers.filter_by(
            provider=provider).first()
        if not connected_provider:
            return

        db.session.delete(connected_provider)


class LocalUser(db.Model):
    user_id = db.Column(
        db.String(80),
        db.ForeignKey(User.id, ondelete='CASCADE'),
        primary_key=True
    )
    password = db.Column(db.String(80), nullable=True)

    user = db.relationship(
        "User", back_populates="local_account", passive_deletes=True)

    @classmethod
    def create(cls, user, password):
        # TODO: Verify password
        hashed_password = flask_bcrypt.generate_password_hash(password)

        instance = cls(user=user, password=hashed_password)
        db.session.add(instance)

        return instance


class ConnectedOidcProvider(db.Model):  # TODO: Add property aud
    user_id = db.Column(
        db.String(80),
        db.ForeignKey(User.id, ondelete='CASCADE'),
        primary_key=True
    )
    provider = db.Column(db.String(80), primary_key=True)
    sub = db.Column(db.String(80))

    user = db.relationship(
        "User", back_populates="connected_providers", passive_deletes=True)

    @classmethod
    def create(cls, user, provider, sub):
        instance = cls(
            user=user,
            provider=provider,
            sub=sub
        )
        db.session.add(instance)

        return instance
