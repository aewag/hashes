#![allow(clippy::unreadable_literal)]

macro_rules! REPEAT4 {
    ($e: expr) => {
        $e;
        $e;
        $e;
        $e;
    };
}

macro_rules! FOR5 {
    ($v: expr, $s: expr, $e: expr) => {
        $v = 0;
        REPEAT4!({
            $e;
            $v += $s;
        });
        $e;
    };
}
