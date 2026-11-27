// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a mocked token provider which only for tests

use async_trait::async_trait;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};

use crate::{Error, Result, TeeKeyPair, Token};

use super::TokenProvider;

#[derive(Default)]
pub struct TestTokenProvider {}

#[async_trait]
impl TokenProvider for TestTokenProvider {
    async fn get_token(&self) -> Result<(Token, TeeKeyPair)> {
        let claims = Claims::create(Duration::from_hours(1));
        let jwt = Ed25519KeyPair::generate()
            .sign(claims)
            .map_err(|e| Error::GetTokenFailed(e.to_string()))?;
        let token = Token::new(jwt).map_err(|e| Error::GetTokenFailed(e.to_string()))?;
        let key = TeeKeyPair::new().map_err(|e| Error::GenerateKeyPairFailed(e.to_string()))?;
        Ok((token, key))
    }
}
