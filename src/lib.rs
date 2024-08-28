use dashmap::DashMap;
use libloading::Library;
use log::info;
use std::any::Any;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[cfg(feature = "async")]
use tokio::fs as async_fs;
#[cfg(feature = "async")]
use tokio::task;

pub struct PluginValue(Box<dyn Any>);

impl PluginValue {
    pub fn new<T: 'static>(value: T) -> Self {
        PluginValue(Box::new(value))
    }

    pub fn downcast<T: 'static>(self) -> Result<T, Self> {
        self.0
            .downcast::<T>()
            .map(|boxed| *boxed)
            .map_err(PluginValue)
    }
}

#[derive(Clone)]
pub struct PluginFunction {
    func: fn(&PluginApi, Option<PluginValue>) -> PluginValue,
}

impl PluginFunction {
    pub fn new(func: fn(&PluginApi, Option<PluginValue>) -> PluginValue) -> Self {
        PluginFunction { func }
    }

    pub fn call(&self, api: &PluginApi, arg: Option<PluginValue>) -> PluginValue {
        (self.func)(api, arg)
    }
}

pub struct PluginApi {
    pub registry: Arc<FunctionRegistry>,
    pub mod_id: u32,
}

impl PluginApi {
    pub fn new(registry: Arc<FunctionRegistry>) -> Self {
        let mod_id = registry.assign_mod_id();
        Self { registry, mod_id }
    }

    pub fn register_function(
        &self,
        name: &str,
        func: fn(&PluginApi, Option<PluginValue>) -> PluginValue,
    ) {
        let wrapped_function = PluginFunction::new(func);
        self.registry
            .register_function(self.mod_id, name, wrapped_function);
    }

    pub fn call_function(&self, function_name: &str, arg: Option<PluginValue>) -> PluginValue {
        self.registry
            .call_function(function_name, self, arg)
            .unwrap_or_else(|| PluginValue::new("Function not found".to_string()))
    }

    pub fn unregister_function(&self, name: &str) {
        self.registry.unregister_function(self.mod_id, name);
    }

    pub fn list_functions(&self) -> DashMap<u32, HashSet<String>> {
        self.registry.list_functions()
    }

    pub fn get_function(&self, name: &str) -> Option<DashMap<u32, PluginFunction>> {
        self.registry.get_function(name)
    }

    #[cfg(not(feature = "async"))]
    pub fn load_plugins(&self, mods_dir: &str) -> Result<(), String> {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let registry = Arc::clone(&self.registry);

        let entries = std::fs::read_dir(mods_dir).map_err(|e| e.to_string())?;

        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some(LIB_EXTENSION) {
                let lib = unsafe { Library::new(&path).map_err(|e| e.to_string())? };

                unsafe {
                    let plugin: libloading::Symbol<*const Plugin> =
                        lib.get(b"PLUGIN\0").map_err(|e| e.to_string())?;
                    let plugin = &**plugin;

                    info!(
                        "Loading plugin: {} v{} by {}",
                        plugin.metadata.name, plugin.metadata.version, plugin.metadata.author
                    );
                    let api = PluginApi::new(registry.clone());
                    (plugin.initialize)(&api);
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn load_plugins(&self, mods_dir: &str) -> Result<(), String> {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let registry = Arc::clone(&self.registry);

        let mut entries = async_fs::read_dir(mods_dir)
            .await
            .map_err(|e| format!("Could not read mods directory: {}", e))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| format!("Failed to read entry: {}", e))?
        {
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some(LIB_EXTENSION) {
                let lib = unsafe {
                    Library::new(&path).map_err(|e| format!("Failed to load library: {}", e))?
                };

                let registry_clone = Arc::clone(&registry);
                task::spawn(async move {
                    unsafe {
                        let plugin: libloading::Symbol<*const Plugin> = lib
                            .get(b"PLUGIN\0")
                            .map_err(|e| format!("Failed to load PLUGIN symbol: {}", e))
                            .unwrap();
                        let plugin = &**plugin;

                        info!(
                            "Loading plugin: {} v{} by {}",
                            plugin.metadata.name, plugin.metadata.version, plugin.metadata.author
                        );
                        let api = PluginApi::new(registry_clone);
                        (plugin.initialize)(&api);
                    }
                })
                .await
                .expect("Failed to load plugin in async task");
            }
        }

        Ok(())
    }
}

pub struct Plugin {
    pub initialize: fn(&PluginApi),
    pub metadata: PluginMetadata,
}

pub struct PluginMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub author: &'static str,
    pub description: &'static str,
}

pub struct FunctionRegistry {
    functions: DashMap<String, DashMap<u32, PluginFunction>>,
    next_mod_id: AtomicU32,
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: DashMap::new(),
            next_mod_id: AtomicU32::new(1),
        }
    }

    fn unregister_function(&self, mod_id: u32, name: &str) {
        if let Some(entry) = self.functions.get_mut(name) {
            if entry.remove(&mod_id).is_some() {
                info!("Unregistered function: {}", name);
            }
        }
    }

    fn register_function(&self, mod_id: u32, original_name: &str, function: PluginFunction) {
        let mut name = original_name.to_string();
        let mut count = 2;

        while self.functions.contains_key(&name) {
            name = format!("{}_{}", original_name, count);
            count += 1;
        }

        self.functions
            .entry(name)
            .or_default()
            .insert(mod_id, function);
    }

    fn get_function(&self, name: &str) -> Option<DashMap<u32, PluginFunction>> {
        self.functions.get(name).map(|entry| entry.clone())
    }

    fn assign_mod_id(&self) -> u32 {
        self.next_mod_id.fetch_add(1, Ordering::SeqCst)
    }

    fn list_functions(&self) -> DashMap<u32, HashSet<String>> {
        let mod_functions = DashMap::new();
        self.functions.iter().for_each(|entry| {
            let (name, mod_map) = entry.pair();
            mod_map.iter().for_each(|mod_entry| {
                let (mod_id, _) = mod_entry.pair();
                mod_functions
                    .entry(*mod_id)
                    .or_insert_with(HashSet::new)
                    .insert(name.clone());
            });
        });
        mod_functions
    }

    fn call_function(
        &self,
        function_name: &str,
        api: &PluginApi,
        arg: Option<PluginValue>,
    ) -> Option<PluginValue> {
        self.functions.get(function_name).and_then(|mod_map| {
            mod_map.iter().next().map(|entry| {
                let (_, func) = entry.pair();
                func.call(api, arg)
            })
        })
    }
}

lazy_static::lazy_static! {
    static ref FUNCTION_REGISTRY: Arc<FunctionRegistry> = Arc::new(FunctionRegistry::new());
}

pub const LIB_EXTENSION: &str = if cfg!(target_os = "windows") {
    "dll"
} else if cfg!(target_os = "macos") {
    "dylib"
} else {
    "so"
};
