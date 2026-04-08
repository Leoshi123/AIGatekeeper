
/**
 * Deep Nesting Stress Test
 * 15+ levels of nesting with a critical vulnerability at the bottom.
 */
function level1() {
    function level2() {
        function level3() {
            function level4() {
                function level5() {
                    function level6() {
                        function level7() {
                            function level8() {
                                function level9() {
                                    function level10() {
                                        function level11() {
                                            function level12() {
                                                function level13() {
                                                    function level14() {
                                                        function level15() {
                                                            // CRITICAL: eval in deep nesting
                                                            eval("console.log('Deeply nested eval executed')");
                                                        }
                                                        return level15();
                                                    }
                                                    return level14();
                                                }
                                                return level13();
                                            }
                                            return level12();
                                        }
                                        return level11();
                                    }
                                    return level10();
                                }
                                return level9();
                            }
                            return level8();
                        }
                        return level7();
                    }
                    return level6();
                }
                return level5();
            }
            return level4();
        }
        return level3();
    }
    return level2();
}
