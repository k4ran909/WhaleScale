//! HTTP client for the coordinator control plane.

use anyhow::Context;
use ws_proto::stats::{LatencySample, ThroughputSample};
use ws_proto::{
    EndpointUpdate, EnrollRequest, EnrollResponse, NetworkMap, RotateRequest, RotateResponse,
};

/// Thin client over the coordinator REST API.
pub struct CoordinatorClient {
    http: reqwest::Client,
    base_url: String,
}

impl CoordinatorClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Enroll this device, returning its assigned identity + session token.
    pub async fn enroll(&self, req: &EnrollRequest) -> anyhow::Result<EnrollResponse> {
        let resp = self
            .http
            .post(format!("{}/enroll", self.base_url))
            .json(req)
            .send()
            .await
            .context("enroll request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("enroll rejected: HTTP {}", resp.status());
        }
        resp.json().await.context("invalid enroll response")
    }

    /// Fetch the current network map using the session token.
    pub async fn netmap(&self, session_token: &str) -> anyhow::Result<NetworkMap> {
        let resp = self
            .http
            .get(format!("{}/netmap", self.base_url))
            .bearer_auth(session_token)
            .send()
            .await
            .context("netmap request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("netmap rejected: HTTP {}", resp.status());
        }
        resp.json().await.context("invalid netmap response")
    }

    /// Rotate the device's WireGuard key, returning the new expiry.
    pub async fn rotate(
        &self,
        session_token: &str,
        req: &RotateRequest,
    ) -> anyhow::Result<RotateResponse> {
        let resp = self
            .http
            .post(format!("{}/rotate", self.base_url))
            .bearer_auth(session_token)
            .json(req)
            .send()
            .await
            .context("rotate request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("rotate rejected: HTTP {}", resp.status());
        }
        resp.json().await.context("invalid rotate response")
    }

    /// Report discovered endpoints (local + STUN reflexive) to the coordinator.
    pub async fn report_endpoints(
        &self,
        session_token: &str,
        update: &EndpointUpdate,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/endpoints", self.base_url))
            .bearer_auth(session_token)
            .json(update)
            .send()
            .await
            .context("endpoints request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("endpoints rejected: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// Report a latency sample (e.g. STUN RTT) to the coordinator.
    pub async fn report_stats(
        &self,
        session_token: &str,
        sample: &LatencySample,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/stats", self.base_url))
            .bearer_auth(session_token)
            .json(sample)
            .send()
            .await
            .context("stats request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("stats rejected: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// Report cumulative interface byte counters to the coordinator.
    pub async fn report_throughput(
        &self,
        session_token: &str,
        sample: &ThroughputSample,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/throughput", self.base_url))
            .bearer_auth(session_token)
            .json(sample)
            .send()
            .await
            .context("throughput request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("throughput rejected: HTTP {}", resp.status());
        }
        Ok(())
    }
}
