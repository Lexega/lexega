
begin
    LET x := 10;
    LET Y := 20;
    while (x < y) DO
        x := x + 1;
    end WHILE;
    for rec IN (SELECT * FROM t1) DO
        INSERT INTO t2
        VALUES (rec.id);
    end FOR;
    RETURN x + y;
end;