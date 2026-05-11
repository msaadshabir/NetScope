use crate::flow::{ExpiredFlowCsvSink, ExpiredFlowEvent};
use crate::jsonl::JsonlSink;
use std::path::Path;

#[derive(Debug)]
pub struct AlertJsonlSink {
    sink: JsonlSink,
}

impl AlertJsonlSink {
    pub fn open(path: &Path) -> Result<Self, std::io::Error> {
        Ok(AlertJsonlSink {
            sink: JsonlSink::new(path).map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!("failed to open alerts jsonl '{}': {}", path.display(), err),
                )
            })?,
        })
    }

    pub fn write_alert(
        &mut self,
        ts: f64,
        kind: &str,
        description: &str,
    ) -> Result<(), std::io::Error> {
        let record = serde_json::json!({
            "ts": ts,
            "kind": kind,
            "description": description,
        });
        self.sink.write(&record).map_err(|err| {
            std::io::Error::new(err.kind(), format!("alert write error: {}", err))
        })?;
        self.sink.flush().map_err(|err| {
            std::io::Error::new(err.kind(), format!("alert flush error: {}", err))
        })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ExpiredFlowSinks {
    jsonl: Option<JsonlSink>,
    csv: Option<ExpiredFlowCsvSink>,
}

impl ExpiredFlowSinks {
    pub fn open(jsonl: Option<&Path>, csv: Option<&Path>) -> Self {
        ExpiredFlowSinks {
            jsonl: open_optional_jsonl_sink(jsonl, "expired flows jsonl"),
            csv: open_optional_csv_sink(csv, "expired flows csv"),
        }
    }

    pub fn enabled(&self) -> bool {
        self.jsonl.is_some() || self.csv.is_some()
    }

    pub fn write_events(&mut self, events: &[ExpiredFlowEvent]) -> Result<(), std::io::Error> {
        if events.is_empty() {
            return Ok(());
        }

        let mut disable_jsonl = false;
        if let Some(sink) = self.jsonl.as_mut() {
            for event in events {
                if let Err(err) = sink.write(event) {
                    tracing::warn!(error = %err, "expired flows jsonl disabled after write error");
                    disable_jsonl = true;
                    break;
                }
            }
            if !disable_jsonl {
                if let Err(err) = sink.flush() {
                    tracing::warn!(error = %err, "expired flows jsonl disabled after flush error");
                    disable_jsonl = true;
                }
            }
        }
        if disable_jsonl {
            self.jsonl = None;
        }

        let mut disable_csv = false;
        if let Some(sink) = self.csv.as_mut() {
            for event in events {
                if let Err(err) = sink.write(event) {
                    tracing::warn!(error = %err, "expired flows csv disabled after write error");
                    disable_csv = true;
                    break;
                }
            }
            if !disable_csv {
                if let Err(err) = sink.flush() {
                    tracing::warn!(error = %err, "expired flows csv disabled after flush error");
                    disable_csv = true;
                }
            }
        }
        if disable_csv {
            self.csv = None;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct OutputSinks {
    pub alerts_jsonl: Option<AlertJsonlSink>,
    pub expired_flows: ExpiredFlowSinks,
}

impl OutputSinks {
    pub fn open(
        alerts_jsonl: Option<&Path>,
        expired_flows_jsonl: Option<&Path>,
        expired_flows_csv: Option<&Path>,
    ) -> Self {
        let alerts_jsonl = match alerts_jsonl {
            Some(path) => match AlertJsonlSink::open(path) {
                Ok(sink) => Some(sink),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "alerts jsonl disabled"
                    );
                    None
                }
            },
            None => None,
        };

        OutputSinks {
            alerts_jsonl,
            expired_flows: ExpiredFlowSinks::open(expired_flows_jsonl, expired_flows_csv),
        }
    }

    pub fn emit_expired_flows(&self) -> bool {
        self.expired_flows.enabled()
    }

    pub fn write_alert(
        &mut self,
        ts: f64,
        kind: &str,
        description: &str,
    ) -> Result<(), std::io::Error> {
        let mut disable_alerts = false;
        if let Some(sink) = self.alerts_jsonl.as_mut() {
            if let Err(err) = sink.write_alert(ts, kind, description) {
                tracing::warn!(error = %err, "alerts jsonl disabled after write error");
                disable_alerts = true;
            }
        }
        if disable_alerts {
            self.alerts_jsonl = None;
        }
        Ok(())
    }

    pub fn write_expired_flows(
        &mut self,
        events: &[ExpiredFlowEvent],
    ) -> Result<(), std::io::Error> {
        self.expired_flows.write_events(events)
    }
}

fn open_optional_jsonl_sink(
    path: Option<&Path>,
    label: &str,
) -> Option<JsonlSink> {
    match path {
        Some(path) => match JsonlSink::new(path) {
            Ok(sink) => Some(sink),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "failed to open {}; output disabled",
                    label
                );
                None
            }
        },
        None => None,
    }
}

fn open_optional_csv_sink(
    path: Option<&Path>,
    label: &str,
) -> Option<ExpiredFlowCsvSink> {
    match path {
        Some(path) => match ExpiredFlowCsvSink::new(path) {
            Ok(sink) => Some(sink),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "failed to open {}; output disabled",
                    label
                );
                None
            }
        },
        None => None,
    }
}
