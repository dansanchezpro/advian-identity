# 🍽️ DISEÑO DE BASE DE DATOS - SISTEMA RESTAURANTE & ALMACÉN

## 📋 **ANÁLISIS DEL SISTEMA**

### **🎯 Objetivos del Sistema:**
- **Vista Cliente**: Menú con productos y precios
- **Vista Cocina**: Recetas con ingredientes genéricos
- **Vista Compras**: Productos específicos con marcas y presentaciones
- **Vista Inventario**: Control de existencias por almacén
- **Cálculo de Costos**: FIFO/LIFO con precios variables

### **🔄 Flujo Principal:**
```
CLIENTE → MENÚ → PRODUCTO → RECETA → INGREDIENTES GENÉRICOS
                                  ↓
ALMACÉN ← INVENTARIO ← PRODUCTOS ESPECÍFICOS ← COMPRAS
```

---

## 🏗️ **ESTRUCTURA DE LA BASE DE DATOS**

### **1️⃣ GESTIÓN DE PRODUCTOS Y MENÚ**

```sql
-- Categorías del menú (Entradas, Platos Principales, Postres, etc.)
CREATE TABLE categorias_menu (
    id INT PRIMARY KEY IDENTITY,
    nombre NVARCHAR(100) NOT NULL,
    descripcion NVARCHAR(500),
    orden_visualizacion INT,
    activo BIT DEFAULT 1,
    fecha_creacion DATETIME2 DEFAULT GETDATE()
);

-- Productos que ve el cliente en el menú
CREATE TABLE productos_menu (
    id INT PRIMARY KEY IDENTITY,
    categoria_id INT FOREIGN KEY REFERENCES categorias_menu(id),
    nombre NVARCHAR(200) NOT NULL,
    descripcion NVARCHAR(1000),
    precio_venta DECIMAL(10,2) NOT NULL,
    imagen_url NVARCHAR(500),
    disponible BIT DEFAULT 1,
    es_preparado BIT DEFAULT 1, -- TRUE = tiene receta, FALSE = producto directo
    tiempo_preparacion_minutos INT,
    calorias INT,
    orden_en_categoria INT,
    fecha_creacion DATETIME2 DEFAULT GETDATE(),
    fecha_actualizacion DATETIME2 DEFAULT GETDATE()
);
```

### **2️⃣ SISTEMA DE RECETAS**

```sql
-- Ingredientes genéricos que usa el chef
CREATE TABLE ingredientes_genericos (
    id INT PRIMARY KEY IDENTITY,
    nombre NVARCHAR(200) NOT NULL,
    descripcion NVARCHAR(500),
    unidad_medida NVARCHAR(50) NOT NULL, -- kg, litros, unidades, gramos, ml
    categoria NVARCHAR(100), -- Proteínas, Vegetales, Lácteos, Especias
    es_perecedero BIT DEFAULT 0,
    tiempo_vida_dias INT, -- Para productos perecederos
    activo BIT DEFAULT 1,
    fecha_creacion DATETIME2 DEFAULT GETDATE()
);

-- Recetas principales
CREATE TABLE recetas (
    id INT PRIMARY KEY IDENTITY,
    producto_menu_id INT FOREIGN KEY REFERENCES productos_menu(id),
    nombre NVARCHAR(200) NOT NULL,
    descripcion NVARCHAR(1000),
    instrucciones NVARCHAR(MAX),
    porciones INT NOT NULL DEFAULT 1,
    tiempo_preparacion_minutos INT,
    dificultad NVARCHAR(50), -- Fácil, Medio, Difícil
    chef_creador NVARCHAR(200),
    version INT DEFAULT 1,
    activa BIT DEFAULT 1,
    fecha_creacion DATETIME2 DEFAULT GETDATE(),
    fecha_actualizacion DATETIME2 DEFAULT GETDATE()
);

-- Ingredientes de cada receta
CREATE TABLE recetas_ingredientes (
    id INT PRIMARY KEY IDENTITY,
    receta_id INT FOREIGN KEY REFERENCES recetas(id),
    ingrediente_generico_id INT FOREIGN KEY REFERENCES ingredientes_genericos(id),
    cantidad DECIMAL(10,3) NOT NULL,
    unidad_medida NVARCHAR(50) NOT NULL,
    es_opcional BIT DEFAULT 0,
    notas NVARCHAR(500),
    orden_en_receta INT
);

-- Sub-recetas (ej: salsa que se usa en varios platos)
CREATE TABLE sub_recetas (
    id INT PRIMARY KEY IDENTITY,
    receta_padre_id INT FOREIGN KEY REFERENCES recetas(id),
    receta_hijo_id INT FOREIGN KEY REFERENCES recetas(id),
    cantidad_utilizada DECIMAL(10,3) NOT NULL,
    unidad_medida NVARCHAR(50) NOT NULL
);
```

### **3️⃣ PRODUCTOS ESPECÍFICOS Y COMPRAS**

```sql
-- Marcas de productos
CREATE TABLE marcas (
    id INT PRIMARY KEY IDENTITY,
    nombre NVARCHAR(200) NOT NULL,
    pais_origen NVARCHAR(100),
    contacto_proveedor NVARCHAR(500),
    activo BIT DEFAULT 1
);

-- Proveedores
CREATE TABLE proveedores (
    id INT PRIMARY KEY IDENTITY,
    nombre NVARCHAR(200) NOT NULL,
    contacto NVARCHAR(200),
    telefono NVARCHAR(50),
    email NVARCHAR(200),
    direccion NVARCHAR(500),
    dias_credito INT DEFAULT 0,
    activo BIT DEFAULT 1,
    fecha_registro DATETIME2 DEFAULT GETDATE()
);

-- Productos específicos que se compran (con marca y presentación)
CREATE TABLE productos_compra (
    id INT PRIMARY KEY IDENTITY,
    ingrediente_generico_id INT FOREIGN KEY REFERENCES ingredientes_genericos(id),
    marca_id INT FOREIGN KEY REFERENCES marcas(id),
    proveedor_id INT FOREIGN KEY REFERENCES proveedores(id),
    nombre_comercial NVARCHAR(300) NOT NULL,
    codigo_barras NVARCHAR(100),
    codigo_proveedor NVARCHAR(100),
    presentacion NVARCHAR(200), -- "Botella 1L", "Saco 25kg", "Caja 12 unidades"
    cantidad_por_presentacion DECIMAL(10,3), -- Cuánto del ingrediente genérico contiene
    unidad_contenida NVARCHAR(50), -- kg, litros, unidades
    precio_compra_actual DECIMAL(10,2),
    moneda NVARCHAR(10) DEFAULT 'PEN',
    activo BIT DEFAULT 1,
    fecha_registro DATETIME2 DEFAULT GETDATE(),
    fecha_ultima_compra DATETIME2
);
```

### **4️⃣ GESTIÓN DE ALMACENES**

```sql
-- Almacenes
CREATE TABLE almacenes (
    id INT PRIMARY KEY IDENTITY,
    nombre NVARCHAR(200) NOT NULL,
    ubicacion NVARCHAR(300),
    tipo NVARCHAR(100), -- Principal, Secundario, Refrigerado, Congelado
    responsable NVARCHAR(200),
    activo BIT DEFAULT 1,
    fecha_creacion DATETIME2 DEFAULT GETDATE()
);

-- Inventario por almacén y producto
CREATE TABLE inventario (
    id INT PRIMARY KEY IDENTITY,
    almacen_id INT FOREIGN KEY REFERENCES almacenes(id),
    producto_compra_id INT FOREIGN KEY REFERENCES productos_compra(id),
    cantidad_actual DECIMAL(10,3) NOT NULL DEFAULT 0,
    cantidad_minima DECIMAL(10,3) DEFAULT 0, -- Para alertas
    cantidad_maxima DECIMAL(10,3) DEFAULT 0, -- Para control
    ubicacion_fisica NVARCHAR(200), -- Estante, refrigerador, etc.
    fecha_ultima_actualizacion DATETIME2 DEFAULT GETDATE(),
    
    UNIQUE(almacen_id, producto_compra_id)
);
```

### **5️⃣ CONTROL DE COMPRAS Y COSTOS**

```sql
-- Órdenes de compra
CREATE TABLE ordenes_compra (
    id INT PRIMARY KEY IDENTITY,
    numero_orden NVARCHAR(50) NOT NULL UNIQUE,
    proveedor_id INT FOREIGN KEY REFERENCES proveedores(id),
    almacen_destino_id INT FOREIGN KEY REFERENCES almacenes(id),
    fecha_orden DATETIME2 DEFAULT GETDATE(),
    fecha_esperada DATETIME2,
    fecha_recibida DATETIME2,
    estado NVARCHAR(50) DEFAULT 'Pendiente', -- Pendiente, Parcial, Completa, Cancelada
    subtotal DECIMAL(12,2),
    impuestos DECIMAL(12,2),
    total DECIMAL(12,2),
    moneda NVARCHAR(10) DEFAULT 'PEN',
    usuario_creador NVARCHAR(200),
    notas NVARCHAR(1000)
);

-- Detalle de órdenes de compra
CREATE TABLE ordenes_compra_detalle (
    id INT PRIMARY KEY IDENTITY,
    orden_compra_id INT FOREIGN KEY REFERENCES ordenes_compra(id),
    producto_compra_id INT FOREIGN KEY REFERENCES productos_compra(id),
    cantidad_pedida DECIMAL(10,3) NOT NULL,
    cantidad_recibida DECIMAL(10,3) DEFAULT 0,
    precio_unitario DECIMAL(10,2) NOT NULL,
    subtotal DECIMAL(12,2) NOT NULL,
    fecha_vencimiento DATETIME2, -- Para productos perecederos
    lote NVARCHAR(100)
);

-- Movimientos de inventario (FIFO/LIFO)
CREATE TABLE movimientos_inventario (
    id INT PRIMARY KEY IDENTITY,
    almacen_id INT FOREIGN KEY REFERENCES almacenes(id),
    producto_compra_id INT FOREIGN KEY REFERENCES productos_compra(id),
    tipo_movimiento NVARCHAR(50) NOT NULL, -- ENTRADA, SALIDA, AJUSTE, MERMA
    cantidad DECIMAL(10,3) NOT NULL,
    costo_unitario DECIMAL(10,2), -- Costo al momento del movimiento
    costo_total DECIMAL(12,2),
    fecha_movimiento DATETIME2 DEFAULT GETDATE(),
    numero_lote NVARCHAR(100),
    fecha_vencimiento DATETIME2,
    orden_compra_detalle_id INT FOREIGN KEY REFERENCES ordenes_compra_detalle(id),
    usuario NVARCHAR(200),
    motivo NVARCHAR(500),
    documento_referencia NVARCHAR(200)
);

-- Lotes para control FIFO
CREATE TABLE lotes_inventario (
    id INT PRIMARY KEY IDENTITY,
    almacen_id INT FOREIGN KEY REFERENCES almacenes(id),
    producto_compra_id INT FOREIGN KEY REFERENCES productos_compra(id),
    numero_lote NVARCHAR(100) NOT NULL,
    cantidad_inicial DECIMAL(10,3) NOT NULL,
    cantidad_disponible DECIMAL(10,3) NOT NULL,
    costo_unitario DECIMAL(10,2) NOT NULL,
    fecha_ingreso DATETIME2 DEFAULT GETDATE(),
    fecha_vencimiento DATETIME2,
    orden_compra_detalle_id INT FOREIGN KEY REFERENCES ordenes_compra_detalle(id),
    activo BIT DEFAULT 1
);
```

### **6️⃣ CÁLCULO DE COSTOS**

```sql
-- Cálculo de costo por receta
CREATE TABLE costos_recetas (
    id INT PRIMARY KEY IDENTITY,
    receta_id INT FOREIGN KEY REFERENCES recetas(id),
    fecha_calculo DATETIME2 DEFAULT GETDATE(),
    costo_ingredientes DECIMAL(12,2),
    costo_mano_obra DECIMAL(12,2) DEFAULT 0,
    costos_indirectos DECIMAL(12,2) DEFAULT 0,
    costo_total DECIMAL(12,2),
    margen_sugerido DECIMAL(5,2), -- Porcentaje
    precio_venta_sugerido DECIMAL(12,2),
    activo BIT DEFAULT 1
);

-- Histórico de precios de productos
CREATE TABLE historial_precios_compra (
    id INT PRIMARY KEY IDENTITY,
    producto_compra_id INT FOREIGN KEY REFERENCES productos_compra(id),
    precio_anterior DECIMAL(10,2),
    precio_nuevo DECIMAL(10,2),
    fecha_cambio DATETIME2 DEFAULT GETDATE(),
    motivo NVARCHAR(500),
    usuario NVARCHAR(200)
);
```

---

## 🔄 **PROCEDIMIENTOS Y VISTAS CLAVE**

### **📊 Vista: Inventario Consolidado**
```sql
CREATE VIEW vw_inventario_consolidado AS
SELECT 
    ig.nombre as ingrediente_generico,
    pc.nombre_comercial,
    m.nombre as marca,
    a.nombre as almacen,
    i.cantidad_actual,
    i.cantidad_minima,
    ig.unidad_medida,
    (SELECT TOP 1 costo_unitario 
     FROM lotes_inventario l 
     WHERE l.producto_compra_id = pc.id 
       AND l.almacen_id = a.id 
       AND l.cantidad_disponible > 0 
     ORDER BY fecha_ingreso ASC) as costo_unitario_fifo
FROM inventario i
INNER JOIN productos_compra pc ON i.producto_compra_id = pc.id
INNER JOIN ingredientes_genericos ig ON pc.ingrediente_generico_id = ig.id
INNER JOIN marcas m ON pc.marca_id = m.id
INNER JOIN almacenes a ON i.almacen_id = a.id
WHERE i.cantidad_actual > 0;
```

### **💰 Función: Calcular Costo de Receta**
```sql
CREATE FUNCTION fn_calcular_costo_receta(@receta_id INT)
RETURNS DECIMAL(12,2)
AS
BEGIN
    DECLARE @costo_total DECIMAL(12,2) = 0;
    
    -- Sumar costos de ingredientes directos
    SELECT @costo_total = @costo_total + SUM(
        ri.cantidad * ISNULL((
            SELECT TOP 1 l.costo_unitario 
            FROM lotes_inventario l
            INNER JOIN productos_compra pc ON l.producto_compra_id = pc.id
            WHERE pc.ingrediente_generico_id = ri.ingrediente_generico_id
              AND l.cantidad_disponible > 0
            ORDER BY l.fecha_ingreso ASC
        ), 0)
    )
    FROM recetas_ingredientes ri
    WHERE ri.receta_id = @receta_id;
    
    -- Sumar costos de sub-recetas (recursivo)
    DECLARE @subreceta_id INT;
    DECLARE @cantidad_sub DECIMAL(10,3);
    
    DECLARE cur_subrecetas CURSOR FOR
    SELECT receta_hijo_id, cantidad_utilizada
    FROM sub_recetas
    WHERE receta_padre_id = @receta_id;
    
    OPEN cur_subrecetas;
    FETCH NEXT FROM cur_subrecetas INTO @subreceta_id, @cantidad_sub;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @costo_total = @costo_total + (@cantidad_sub * dbo.fn_calcular_costo_receta(@subreceta_id));
        FETCH NEXT FROM cur_subrecetas INTO @subreceta_id, @cantidad_sub;
    END;
    
    CLOSE cur_subrecetas;
    DEALLOCATE cur_subrecetas;
    
    RETURN @costo_total;
END;
```

### **📦 Procedimiento: Consumir Ingrediente (FIFO)**
```sql
CREATE PROCEDURE sp_consumir_ingrediente
    @almacen_id INT,
    @ingrediente_generico_id INT,
    @cantidad_consumir DECIMAL(10,3),
    @motivo NVARCHAR(500)
AS
BEGIN
    DECLARE @cantidad_restante DECIMAL(10,3) = @cantidad_consumir;
    DECLARE @lote_id INT, @cantidad_disponible DECIMAL(10,3), @costo_unitario DECIMAL(10,2);
    
    -- Cursor para consumir lotes en orden FIFO
    DECLARE cur_lotes CURSOR FOR
    SELECT l.id, l.cantidad_disponible, l.costo_unitario
    FROM lotes_inventario l
    INNER JOIN productos_compra pc ON l.producto_compra_id = pc.id
    WHERE l.almacen_id = @almacen_id 
      AND pc.ingrediente_generico_id = @ingrediente_generico_id
      AND l.cantidad_disponible > 0
      AND l.activo = 1
    ORDER BY l.fecha_ingreso ASC;
    
    OPEN cur_lotes;
    FETCH NEXT FROM cur_lotes INTO @lote_id, @cantidad_disponible, @costo_unitario;
    
    WHILE @@FETCH_STATUS = 0 AND @cantidad_restante > 0
    BEGIN
        DECLARE @cantidad_a_consumir DECIMAL(10,3);
        
        IF @cantidad_disponible >= @cantidad_restante
            SET @cantidad_a_consumir = @cantidad_restante;
        ELSE
            SET @cantidad_a_consumir = @cantidad_disponible;
        
        -- Actualizar lote
        UPDATE lotes_inventario 
        SET cantidad_disponible = cantidad_disponible - @cantidad_a_consumir
        WHERE id = @lote_id;
        
        -- Registrar movimiento
        INSERT INTO movimientos_inventario 
        (almacen_id, producto_compra_id, tipo_movimiento, cantidad, costo_unitario, costo_total, motivo)
        SELECT @almacen_id, pc.id, 'SALIDA', @cantidad_a_consumir, @costo_unitario, 
               @cantidad_a_consumir * @costo_unitario, @motivo
        FROM lotes_inventario l
        INNER JOIN productos_compra pc ON l.producto_compra_id = pc.id
        WHERE l.id = @lote_id;
        
        SET @cantidad_restante = @cantidad_restante - @cantidad_a_consumir;
        FETCH NEXT FROM cur_lotes INTO @lote_id, @cantidad_disponible, @costo_unitario;
    END;
    
    CLOSE cur_lotes;
    DEALLOCATE cur_lotes;
    
    -- Actualizar inventario consolidado
    UPDATE inventario 
    SET cantidad_actual = cantidad_actual - (@cantidad_consumir - @cantidad_restante)
    WHERE almacen_id = @almacen_id 
      AND producto_compra_id IN (
          SELECT id FROM productos_compra 
          WHERE ingrediente_generico_id = @ingrediente_generico_id
      );
END;
```

---

## 🎯 **CASOS DE USO PRINCIPALES**

### **1️⃣ Cliente ve el menú:**
```sql
SELECT 
    c.nombre as categoria,
    p.nombre,
    p.descripcion,
    p.precio_venta,
    p.disponible,
    p.tiempo_preparacion_minutos
FROM productos_menu p
INNER JOIN categorias_menu c ON p.categoria_id = c.id
WHERE p.disponible = 1 AND c.activo = 1
ORDER BY c.orden_visualizacion, p.orden_en_categoria;
```

### **2️⃣ Chef ve la receta:**
```sql
SELECT 
    r.nombre as receta,
    ig.nombre as ingrediente,
    ri.cantidad,
    ri.unidad_medida,
    ri.es_opcional,
    ri.notas
FROM recetas r
INNER JOIN recetas_ingredientes ri ON r.id = ri.receta_id
INNER JOIN ingredientes_genericos ig ON ri.ingrediente_generico_id = ig.id
WHERE r.producto_menu_id = @producto_id
  AND r.activa = 1
ORDER BY ri.orden_en_receta;
```

### **3️⃣ Comprador ve productos específicos:**
```sql
SELECT 
    ig.nombre as ingrediente_base,
    pc.nombre_comercial,
    m.nombre as marca,
    pc.presentacion,
    pc.precio_compra_actual,
    pr.nombre as proveedor,
    i.cantidad_actual,
    i.cantidad_minima
FROM productos_compra pc
INNER JOIN ingredientes_genericos ig ON pc.ingrediente_generico_id = ig.id
INNER JOIN marcas m ON pc.marca_id = m.id
INNER JOIN proveedores pr ON pc.proveedor_id = pr.id
LEFT JOIN inventario i ON pc.id = i.producto_compra_id
WHERE pc.activo = 1;
```

### **4️⃣ Calcular costo real del plato:**
```sql
SELECT 
    p.nombre as plato,
    p.precio_venta,
    dbo.fn_calcular_costo_receta(r.id) as costo_real,
    p.precio_venta - dbo.fn_calcular_costo_receta(r.id) as ganancia,
    ((p.precio_venta - dbo.fn_calcular_costo_receta(r.id)) / p.precio_venta * 100) as margen_porcentaje
FROM productos_menu p
INNER JOIN recetas r ON p.id = r.producto_menu_id
WHERE r.activa = 1;
```

---

## ⚠️ **CONSIDERACIONES IMPORTANTES**

### **🔒 Integridad de Datos:**
- Constraints de foreign keys
- Validaciones de cantidades positivas
- Triggers para actualizar inventario automáticamente

### **📈 Performance:**
- Índices en campos de búsqueda frecuente
- Particionado de tablas de movimientos por fecha
- Archivado de datos históricos

### **🔄 Concurrencia:**
- Locks en movimientos de inventario
- Transacciones para operaciones críticas
- Control de versiones en recetas

### **📊 Reportes Clave:**
- Inventario valorizado
- Productos próximos a vencer
- Análisis de rentabilidad por plato
- Rotación de inventario
- Sugerencias de compra automáticas

---

## 🚀 **PRÓXIMOS PASOS**

1. **Implementar la estructura base**
2. **Crear stored procedures de negocio**
3. **Desarrollar triggers de auditoría**
4. **Implementar sistema de alertas**
5. **Crear vistas de reportes**
6. **Optimizar con índices**
7. **Implementar respaldos automáticos**

**¡Este diseño te permitirá manejar todo el flujo desde el menú del cliente hasta el control detallado de costos y inventarios! 🎯**